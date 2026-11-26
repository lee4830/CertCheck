using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace CertificateChecker;

public record CertificateInfo(string Subject, string Issuer, string Serial, DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc, string Signature, string Sha256, string San, byte[] Der, string Status)
{
    public static CertificateInfo From(X509Certificate2 cert, string status = "") => new(
        cert.Subject, cert.Issuer, cert.SerialNumber, cert.NotBefore.ToUniversalTime(), cert.NotAfter.ToUniversalTime(),
        cert.SignatureAlgorithm.FriendlyName ?? cert.SignatureAlgorithm.Value ?? "", cert.GetCertHashString(HashAlgorithmName.SHA256),
        string.Join("\n", cert.Extensions.Where(x => x.Oid?.Value == "2.5.29.17").Select(x => x.Format(true))), cert.RawData, status);
    public string Pem => PemEncoding.WriteString("CERTIFICATE", Der);
}
public sealed class ProbeResult
{
    public Target Target { get; set; } = new("", 443, "", false);
    public DateTimeOffset CheckedUtc { get; set; } = DateTimeOffset.UtcNow;
    public string[] DnsAddresses { get; set; } = [];
    public string RemoteEndpoint { get; set; } = "";
    public string TlsVersion { get; set; } = "";
    public string CipherSuite { get; set; } = "";
    public bool HandshakeComplete { get; set; }
    public bool? HostnameMatch { get; set; }
    public bool? OsChainValid { get; set; }
    public string[] OsErrors { get; set; } = [];
    public string Error { get; set; } = "";
    public List<CertificateInfo> ServerChain { get; set; } = [];
    public List<CertificateInfo> OsChain { get; set; } = [];
    public string ValidationSummary => !HandshakeComplete ? "연결 미완료" : HostnameMatch != true || OsChainValid != true ? "검증 실패"
        : Target.OnlineRevocation ? "검증 정상" : "검증 정상 · 폐기 미검사";
    public string Json() => JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
    public string Report()
    {
        var b = new System.Text.StringBuilder();
        b.AppendLine("SSL Certificate Checker 1.0").AppendLine($"조회: {Dates.Kst(CheckedUtc)}")
            .AppendLine($"접속 대상: {Target.Host}:{Target.Port}")
            .AppendLine($"검증 이름: {Target.Identity} | SNI: {(Target.SendSni ? Target.Identity : "전송 안 함")}")
            .AppendLine($"DNS: {string.Join(", ", DnsAddresses)}").AppendLine($"실제 접속: {RemoteEndpoint}")
            .AppendLine($"TLS: {TlsVersion} / {CipherSuite} | 핸드셰이크: {(HandshakeComplete ? "완료" : "미완료")}")
            .AppendLine($"호스트명(SAN 기준): {Flag(HostnameMatch)} | Windows 체인: {Flag(OsChainValid)}")
            .AppendLine($"폐기 검사: {(Target.OnlineRevocation ? "온라인 요청 (결과는 체인 상태 참조)" : "수행 안 함")}; AIA 인증서 다운로드: 비활성")
            .AppendLine("Windows 저장소/캐시 상태에 따라 OS 체인이 달라질 수 있습니다.");
        if (Error.Length > 0) b.AppendLine($"연결 오류: {Error}");
        foreach (string error in OsErrors) b.AppendLine($"검증 오류: {error}");
        AddChain("실제 서버 전송 체인 (TLS Certificate 메시지 순서)", ServerChain);
        AddChain("Windows OS 검증 체인 (서버 전송 목록과 다를 수 있음)", OsChain);
        return b.ToString();
        void AddChain(string title, List<CertificateInfo> certs)
        {
            b.AppendLine().AppendLine($"{title} — {certs.Count}개");
            for (int i = 0; i < certs.Count; i++) {
                var c = certs[i];
                b.AppendLine($"[{i + 1}] {c.Subject}").AppendLine($"발급자: {c.Issuer}")
                    .AppendLine($"시작: {Dates.Kst(c.NotBeforeUtc)}").AppendLine($"만료: {Dates.Kst(c.NotAfterUtc)} ({Dates.Dday(c.NotAfterUtc, CheckedUtc)})")
                    .AppendLine($"일련번호: {c.Serial}").AppendLine($"서명: {c.Signature}")
                    .AppendLine($"SHA-256: {c.Sha256}").AppendLine($"SAN:\n{c.San}").AppendLine($"상태: {c.Status}");
            }
        }
    }
    private static string Flag(bool? value) => value.HasValue ? (value.Value ? "정상" : "실패") : "확인 못함";
}
