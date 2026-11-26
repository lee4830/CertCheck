using System.Text;

namespace CertificateChecker;

public enum ExportFormat { Json, Text, ServerPem, CertificateDer }
public static class Exports
{
    public static void Save(ProbeResult result, ExportFormat format, string path, CertificateInfo? selected = null)
    {
        switch (format) {
            case ExportFormat.Json: File.WriteAllText(path, result.Json(), new UTF8Encoding(false)); break;
            case ExportFormat.Text: File.WriteAllText(path, result.Report(), new UTF8Encoding(false)); break;
            case ExportFormat.ServerPem:
                if (result.ServerChain.Count == 0) throw new InvalidOperationException("서버에서 수집한 인증서가 없습니다.");
                File.WriteAllText(path, string.Join(Environment.NewLine, result.ServerChain.Select(c => c.Pem)), Encoding.ASCII); break;
            case ExportFormat.CertificateDer:
                if (selected is null) throw new InvalidOperationException("내보낼 인증서를 선택하세요.");
                File.WriteAllBytes(path, selected.Der); break;
            default: throw new ArgumentOutOfRangeException(nameof(format));
        }
    }
}
