using System.Globalization;
using System.Net;

namespace CertificateChecker;

public record Target(string Host, int Port, string Identity, bool SendSni, int TimeoutSeconds = 15, bool OnlineRevocation = false)
{
    public static Target Parse(string host, int port, string sni, bool sendSni, int timeout = 15, bool online = false)
    {
        if (port is < 1 or > 65535) throw new ArgumentException("포트는 1~65535 범위여야 합니다.");
        if (timeout is < 1 or > 60) throw new ArgumentException("제한 시간은 1~60초여야 합니다.");
        host = Normalize(host);
        var identity = string.IsNullOrWhiteSpace(sni) ? host : Normalize(sni);
        if (!string.IsNullOrWhiteSpace(sni) && IPAddress.TryParse(identity, out _))
            throw new ArgumentException("SNI에는 IP 대신 DNS 이름을 입력하세요. IP 검증은 SNI를 비워 두세요.");
        return new(host, port, identity, sendSni && !IPAddress.TryParse(identity, out _), timeout, online);
    }
    private static string Normalize(string value)
    {
        value = value.Trim();
        if (value.StartsWith('[') && value.EndsWith(']')) value = value[1..^1];
        if (IPAddress.TryParse(value, out var ip)) return ip.ToString();
        try { value = new IdnMapping().GetAscii(value.TrimEnd('.')).ToLowerInvariant(); }
        catch (ArgumentException) { throw new ArgumentException("올바른 도메인 또는 IP를 입력하세요."); }
        if (value.Length is 0 or > 253 || value.Split('.').Any(l => l.Length is 0 or > 63 || l.StartsWith('-') || l.EndsWith('-') || l.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-')))
            throw new ArgumentException("도메인 또는 IP만 입력하세요. URL, 경로, 포트는 포함하지 마세요.");
        return value;
    }
}
public static class Dates
{
    public static string Kst(DateTimeOffset value) => value.ToOffset(TimeSpan.FromHours(9)).ToString("yyyy-MM-dd HH:mm:ss 'KST'", CultureInfo.InvariantCulture);
    public static string Dday(DateTimeOffset expires, DateTimeOffset now)
    {
        if (expires <= now) return "만료됨";
        int days = (int)Math.Floor((expires - now).TotalDays);
        return days == 0 ? "D-Day (24시간 미만)" : $"D-{days}";
    }
}
