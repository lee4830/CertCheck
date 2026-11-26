using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertificateChecker;

static class TlsTests
{
    public static void Run(Action<string, Action> test)
    {
        test("Expired untrusted certificate retained; independent hostname validation", () => Check(true, false).GetAwaiter().GetResult());
        test("Exact transmitted chain and SNI are captured in a single TLS connection", () => Check(false, true).GetAwaiter().GetResult());
        test("TLS 1.3 certificate chain is collected", () => Check(false, true, tls13: true).GetAwaiter().GetResult());
        test("Disabling SNI still validates configured DNS identity", () => Check(false, true, noSni: true).GetAwaiter().GetResult());
        test("Probe never posts blocking chain work to caller UI context", () => Check(false, true, checkContext: true).GetAwaiter().GetResult());
        test("Timeout stops a silent TLS server", () => Silent(false).GetAwaiter().GetResult());
        test("User cancellation stops a silent TLS server", () => Silent(true).GetAwaiter().GetResult());
        test("Connection refused returns diagnostic result", () => Refused().GetAwaiter().GetResult());
    }
    static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
    static CertificateRequest Request(string name, RSA key, bool ca)
    {
        var r = new CertificateRequest($"CN={name}", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        r.CertificateExtensions.Add(new X509BasicConstraintsExtension(ca, false, 0, true));
        r.CertificateExtensions.Add(new X509KeyUsageExtension(ca ? X509KeyUsageFlags.KeyCertSign : X509KeyUsageFlags.DigitalSignature, true));
        if (!ca) {
            var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("localhost"); r.CertificateExtensions.Add(san.Build());
            r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
        }
        return r;
    }
    static async Task Check(bool expired, bool withIntermediate, bool tls13 = false, bool noSni = false, bool checkContext = false)
    {
        using var rootKey = RSA.Create(2048); using var interKey = RSA.Create(2048); using var leafKey = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        using var root = Request("Checker Test Root", rootKey, true).CreateSelfSigned(now.AddDays(-60), now.AddDays(60));
        using var interPublic = Request("Checker Intermediate", interKey, true).Create(root, now.AddDays(-50), now.AddDays(50), RandomNumberGenerator.GetBytes(16));
        using var inter = interPublic.CopyWithPrivateKey(interKey);
        using var leafPublic = Request("localhost", leafKey, false).Create(withIntermediate ? inter : root, now.AddDays(-20), expired ? now.AddDays(-1) : now.AddDays(20), RandomNumberGenerator.GetBytes(16));
        using var leafWithKey = leafPublic.CopyWithPrivateKey(leafKey);
        using var leaf = X509CertificateLoader.LoadPkcs12(leafWithKey.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.DefaultKeySet);
        var extras = new X509Certificate2Collection(); if (withIntermediate) extras.Add(inter);
        var context = SslStreamCertificateContext.Create(leaf, extras, offline: true);
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        string? observedSni = null;
        var server = Task.Run(async () => {
            using var tcp = await listener.AcceptTcpClientAsync(); using var ssl = new SslStream(tcp.GetStream());
            await ssl.AuthenticateAsServerAsync((_, hello, _, _) => {
                observedSni = hello.ServerName;
                return ValueTask.FromResult(new SslServerAuthenticationOptions {
                    ServerCertificateContext = context, EnabledSslProtocols = tls13 ? SslProtocols.Tls13 : SslProtocols.Tls12
                });
            }, null, CancellationToken.None);
        });
        var callerContext = new RecordingContext();
        var priorContext = SynchronizationContext.Current;
        Task<ProbeResult> query;
        try {
            if (checkContext) SynchronizationContext.SetSynchronizationContext(callerContext);
            query = Probe.QueryAsync(Target.Parse("127.0.0.1", port, withIntermediate ? "localhost" : "wrong.local", !noSni));
        } finally { SynchronizationContext.SetSynchronizationContext(priorContext); }
        var result = await query;
        if (checkContext) Assert(callerContext.Posts == 0, $"Probe captured caller UI context {callerContext.Posts} times");
        Assert(result.HandshakeComplete, $"Handshake before server wait: {result.Error}");
        await server.WaitAsync(TimeSpan.FromSeconds(10));
        Assert(result.HandshakeComplete, $"Handshake: {result.Error}");
        Assert(result.ServerChain.Count == (withIntermediate ? 2 : 1), $"Wire chain count {result.ServerChain.Count}");
        Assert(result.ServerChain[0].Der.SequenceEqual(leaf.RawData), "Leaf differs");
        if (withIntermediate) Assert(result.ServerChain[1].Der.SequenceEqual(inter.RawData), "Intermediate differs");
        Assert(noSni ? string.IsNullOrEmpty(observedSni) : observedSni == (withIntermediate ? "localhost" : "wrong.local"), $"SNI: {observedSni}");
        Assert(result.TlsVersion == (tls13 ? "TLS 1.3" : "TLS 1.2"), $"Protocol: {result.TlsVersion}");
        Assert(result.HostnameMatch == withIntermediate, "Hostname result incorrect");
        Assert(result.OsChainValid == false, "Local test CA must not be trusted");
        Assert(result.OsErrors.Length > 0, "Missing trust errors");
        if (expired) Assert(result.ServerChain[0].NotAfterUtc < now, "Expired cert lost");
        Assert(result.RemoteEndpoint.Contains("127.0.0.1"), "Missing actual address");
        using var exported = X509CertificateLoader.LoadCertificate(System.Text.Encoding.ASCII.GetBytes(result.ServerChain[0].Pem));
        Assert(exported.RawData.SequenceEqual(leaf.RawData), "PEM export changed DER");
        var roundtrip = System.Text.Json.JsonSerializer.Deserialize<ProbeResult>(result.Json())!;
        Assert(roundtrip.ServerChain[0].Der.SequenceEqual(leaf.RawData), "JSON export changed DER");
        var exportDir = Path.Combine(Path.GetTempPath(), "CheckerExports-" + Guid.NewGuid()); Directory.CreateDirectory(exportDir);
        try {
            Exports.Save(result, ExportFormat.CertificateDer, Path.Combine(exportDir, "leaf.cer"), result.ServerChain[0]);
            using var cer = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(exportDir, "leaf.cer"));
            Assert(cer.RawData.SequenceEqual(leaf.RawData), "CER file changed DER");
            Exports.Save(result, ExportFormat.ServerPem, Path.Combine(exportDir, "chain.pem"));
            var pemCerts = new X509Certificate2Collection(); pemCerts.ImportFromPemFile(Path.Combine(exportDir, "chain.pem"));
            try { Assert(pemCerts.Count == result.ServerChain.Count && pemCerts[0].RawData.SequenceEqual(leaf.RawData), "PEM file lost order/chain"); }
            finally { foreach (var pemCert in pemCerts) pemCert.Dispose(); }
            Exports.Save(result, ExportFormat.Json, Path.Combine(exportDir, "result.json"));
            Assert(System.Text.Json.JsonSerializer.Deserialize<ProbeResult>(File.ReadAllText(Path.Combine(exportDir, "result.json")))!.Target == result.Target, "JSON file lost target");
            Exports.Save(result, ExportFormat.Text, Path.Combine(exportDir, "result.txt"));
            Assert(File.ReadAllText(Path.Combine(exportDir, "result.txt")).Contains("실제 서버 전송 체인"), "Text file encoding/report lost");
        } finally { Directory.Delete(exportDir, true); }
    }
    sealed class RecordingContext : SynchronizationContext
    {
        public int Posts;
        public override void Post(SendOrPostCallback callback, object? state) {
            Interlocked.Increment(ref Posts); ThreadPool.QueueUserWorkItem(_ => callback(state));
        }
    }
    static async Task Silent(bool cancel)
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start();
        using var cts = new CancellationTokenSource(); if (cancel) cts.CancelAfter(200);
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var pending = Probe.QueryAsync(Target.Parse("127.0.0.1", ((IPEndPoint)listener.LocalEndpoint).Port, "", false, cancel ? 15 : 1), cts.Token);
        using var peer = await listener.AcceptTcpClientAsync();
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(5));
        Assert(!result.HandshakeComplete && result.Error.Length > 0, "Silent connection incorrectly succeeded");
        Assert(clock.Elapsed.TotalSeconds < 4, "Cancellation/timeout too slow");
    }
    static async Task Refused()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); int port = ((IPEndPoint)listener.LocalEndpoint).Port; listener.Stop();
        var result = await Probe.QueryAsync(Target.Parse("127.0.0.1", port, "", false, 2));
        Assert(result.Error.Length > 0 && result.ServerChain.Count == 0, "Refused connection lost diagnostics");
    }
}
