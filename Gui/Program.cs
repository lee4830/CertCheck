using CertificateChecker;
namespace CertificateChecker.Gui;

static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length > 0) {
            if (args.Length != 5 || args[0] != "--probe" || !int.TryParse(args[2], out int port)) return 64;
            try {
                var target = Target.Parse(args[1], port, args[3] == "-" ? "" : args[3], true);
                var result = Probe.QueryAsync(target).GetAwaiter().GetResult();
                Exports.Save(result, ExportFormat.Json, args[4]);
                return result.HandshakeComplete ? (result.HostnameMatch == true && result.OsChainValid == true ? 0 : 2) : 1;
            } catch (Exception e) {
                File.WriteAllText(args[4], System.Text.Json.JsonSerializer.Serialize(new { Error = e.Message })); return 1;
            }
        }
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
        return 0;
    }
}
