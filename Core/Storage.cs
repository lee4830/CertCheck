using System.Text.Json;

namespace CertificateChecker;

public sealed class HistoryStore(string path)
{
    public string? Warning { get; private set; }
    public List<ProbeResult> Read()
    {
        Warning = null;
        try {
            if (!File.Exists(path)) return [];
            if (new FileInfo(path).Length > 20_000_000) throw new InvalidDataException("이력 파일이 너무 큽니다.");
            var entries = JsonSerializer.Deserialize<List<ProbeResult>>(File.ReadAllText(path)) ?? throw new InvalidDataException("빈 이력 파일");
            if (entries.Any(r => r is null || r.Target is null || r.ServerChain is null || r.OsChain is null || r.DnsAddresses is null || r.OsErrors is null || r.Error is null))
                throw new InvalidDataException("이력 형식이 올바르지 않습니다.");
            foreach (var r in entries) {
                var t = r.Target;
                if (string.IsNullOrWhiteSpace(t.Host) || string.IsNullOrWhiteSpace(t.Identity)) throw new InvalidDataException("잘못된 이력 대상");
                var normalized = Target.Parse(t.Host, t.Port, t.Identity == t.Host ? "" : t.Identity, t.SendSni, t.TimeoutSeconds, t.OnlineRevocation);
                if (normalized != t) throw new InvalidDataException("정규화되지 않은 이력 대상");
                if (r.RemoteEndpoint is null || r.TlsVersion is null || r.CipherSuite is null || r.DnsAddresses.Any(a => a is null) || r.OsErrors.Any(a => a is null)
                    || r.ServerChain.Concat(r.OsChain).Any(c => c is null || c.Subject is null || c.Issuer is null || c.Serial is null || c.Signature is null || c.Sha256 is null || c.San is null || c.Status is null || c.Der is not { Length: > 0 }))
                    throw new InvalidDataException("잘못된 이력 인증서/연결 정보");
            }
            return entries.Take(50).ToList();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or ArgumentException) {
            Warning = $"이력을 읽지 못했습니다: {e.Message}"; return [];
        }
    }
    public void Add(ProbeResult result)
    {
        var list = Read();
        list.RemoveAll(r => r.Target == result.Target);
        list.Insert(0, result);
        Write(list.Take(50).ToList());
    }
    public void Clear() { if (File.Exists(path)) File.Delete(path); Warning = null; }
    private void Write(List<ProbeResult> list)
    {
        var fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        var temporary = fullPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try { File.WriteAllText(temporary, JsonSerializer.Serialize(list)); File.Move(temporary, fullPath, true); }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
