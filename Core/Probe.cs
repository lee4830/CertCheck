using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace CertificateChecker;

public static class Probe
{
    public static async Task<ProbeResult> QueryAsync(Target target, CancellationToken cancellation = default)
    {
        var result = new ProbeResult { Target = target };
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        deadline.CancelAfter(TimeSpan.FromSeconds(target.TimeoutSeconds));
        using var tcp = new TcpClient();
        using var registration = deadline.Token.Register(() => tcp.Dispose());
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(target.Host, deadline.Token).ConfigureAwait(false);
            result.DnsAddresses = addresses.Select(a => a.ToString()).ToArray();
            await tcp.ConnectAsync(addresses, target.Port, deadline.Token).ConfigureAwait(false);
            result.RemoteEndpoint = tcp.Client.RemoteEndPoint?.ToString() ?? "";
            await Task.Run(() =>
            {
                var protocol = new TlsClientProtocol(tcp.GetStream());
                var client = new CaptureClient(target, result);
                protocol.Connect(client);
                result.HandshakeComplete = true;
                try { protocol.Close(); } catch (IOException) { /* The peer may already have closed the diagnostic connection. */ }
            }).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            result.Error = cancellation.IsCancellationRequested ? "사용자가 조회를 취소했습니다." : deadline.IsCancellationRequested
                ? $"DNS/TCP/TLS 제한 시간({target.TimeoutSeconds}초)을 초과했습니다."
                : $"{e.GetType().Name}: {e.Message}";
        }
        if (result.ServerChain.Count > 0)
        {
            // X509Chain.Build can perform blocking revocation I/O; never execute it on the UI thread.
            try { await Task.Run(() => Validate(result)).ConfigureAwait(false); }
            catch (Exception e) { result.OsErrors = [$"검증 처리 오류: {e.Message}"]; result.OsChainValid = false; }
        }
        return result;
    }

    private static void Validate(ProbeResult result)
    {
        var certs = new List<X509Certificate2>();
        try
        {
            certs.AddRange(result.ServerChain.Select(c => X509CertificateLoader.LoadCertificate(c.Der)));
            result.HostnameMatch = certs[0].MatchesHostname(result.Target.Identity, allowWildcards: true, allowCommonName: false);
            using var chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.AddRange(certs.Skip(1).ToArray());
            chain.ChainPolicy.RevocationMode = result.Target.OnlineRevocation ? X509RevocationMode.Online : X509RevocationMode.NoCheck;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
            chain.ChainPolicy.VerificationTime = result.CheckedUtc.UtcDateTime;
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.1"));
            result.OsChainValid = chain.Build(certs[0]);
            result.OsErrors = chain.ChainStatus.Select(s => $"{s.Status}: {s.StatusInformation.Trim()}").ToArray();
            result.OsChain = chain.ChainElements.Cast<X509ChainElement>().Select(e => CertificateInfo.From(e.Certificate,
                string.Join("; ", e.ChainElementStatus.Select(s => $"{s.Status}: {s.StatusInformation.Trim()}")))).ToList();
        }
        finally { foreach (var cert in certs) cert.Dispose(); }
    }

    private sealed class CaptureClient(Target target, ProbeResult result) : DefaultTlsClient(new BcTlsCrypto())
    {
        protected override ProtocolVersion[] GetSupportedVersions() => [ProtocolVersion.TLSv13, ProtocolVersion.TLSv12];
        protected override IList<ServerName>? GetSniServerNames() => target.SendSni
            ? new List<ServerName> { new(NameType.host_name, Encoding.ASCII.GetBytes(target.Identity)) } : null;
        public override int GetHandshakeTimeoutMillis() => target.TimeoutSeconds * 1000;
        public override TlsAuthentication GetAuthentication() => new CaptureAuthentication(result);
        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();
            result.TlsVersion = m_context.SecurityParameters.NegotiatedVersion.ToString();
            result.CipherSuite = $"0x{m_context.SecurityParameters.CipherSuite:X4}";
        }
    }
    private sealed class CaptureAuthentication(ProbeResult result) : TlsAuthentication
    {
        // Collection is diagnostic only. Trust and identity are evaluated separately by Windows.
        public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
        {
            foreach (var tlsCert in serverCertificate.Certificate.GetCertificateList())
            {
                using var cert = X509CertificateLoader.LoadCertificate(tlsCert.GetEncoded());
                result.ServerChain.Add(CertificateInfo.From(cert));
            }
        }
        public TlsCredentials? GetClientCredentials(Org.BouncyCastle.Tls.CertificateRequest certificateRequest) => null;
    }
}
