using CertificateChecker;

static class StorageTests
{
    public static void Run(Action<string, Action> test)
    {
        test("History persists, caps at 50, deduplicates target and clears", () => {
            var dir = Path.Combine(Path.GetTempPath(), "CheckerTests-" + Guid.NewGuid());
            try {
                var store = new HistoryStore(Path.Combine(dir, "history.json"));
                for (int i = 0; i < 52; i++) store.Add(new ProbeResult { Target = Target.Parse($"host{i}.test", 443, "", true) });
                var list = store.Read();
                if (list.Count != 50 || list[0].Target.Host != "host51.test" || list[^1].Target.Host != "host2.test") throw new Exception("History cap/order failed");
                var last = new ProbeResult { Target = Target.Parse("host30.test", 443, "", true), Error = "new result" };
                store.Add(last); list = new HistoryStore(Path.Combine(dir, "history.json")).Read();
                if (list.Count != 50 || list[0].Error != "new result" || list.Count(x => x.Target.Host == "host30.test") != 1) throw new Exception("History dedup/persistence failed");
                store.Clear(); if (store.Read().Count != 0) throw new Exception("History not cleared");
            } finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
        });
        test("Corrupt history is nonfatal and reports warning", () => {
            var dir = Path.Combine(Path.GetTempPath(), "CheckerTests-" + Guid.NewGuid()); Directory.CreateDirectory(dir);
            try {
                string path = Path.Combine(dir, "history.json"); File.WriteAllText(path, "{broken"); var store = new HistoryStore(path);
                if (store.Read().Count != 0 || string.IsNullOrEmpty(store.Warning)) throw new Exception("Corruption not surfaced safely");
                File.WriteAllText(path, "[{\"Target\":{\"Host\":\"example.com\",\"Port\":443,\"Identity\":\"example.com\",\"SendSni\":true},\"ServerChain\":[null]}]");
                if (store.Read().Count != 0 || string.IsNullOrEmpty(store.Warning)) throw new Exception("Null certificate entry accepted");
                File.WriteAllText(path, "[{\"Target\":{\"Host\":\"example.com\",\"Port\":0,\"Identity\":\"example.com\",\"SendSni\":true}}]");
                if (store.Read().Count != 0 || string.IsNullOrEmpty(store.Warning)) throw new Exception("Invalid target port accepted");
            } finally { Directory.Delete(dir, true); }
        });
    }
}
