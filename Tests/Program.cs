using CertificateChecker;

var failed = 0;
void Test(string name, Action body) { try { body(); Console.WriteLine($"PASS {name}"); } catch (Exception e) { failed++; Console.WriteLine($"FAIL {name}: {e.Message}"); } }
void Equal<T>(T actual, T expected) { if (!EqualityComparer<T>.Default.Equals(actual, expected)) throw new Exception($"Expected {expected}, got {actual}"); }
void Reject(Action body) { try { body(); } catch (ArgumentException) { return; } throw new Exception("Invalid input accepted"); }
Test("Normalize IDN, keep connection host distinct from SNI", () => {
    var t = Target.Parse(" 127.0.0.1 ", 8443, "예시.한국", true);
    Equal(t.Host, "127.0.0.1"); Equal(t.Identity, "xn--vv4b11d.xn--3e0b707e"); Equal(t.SendSni, true);
});
Test("Reject URL, path, invalid port, and IP as explicit SNI", () => {
    Reject(() => Target.Parse("https://example.com", 443, "", true));
    Reject(() => Target.Parse("a/b", 443, "", true));
    Reject(() => Target.Parse("example.com", 0, "", true));
    Reject(() => Target.Parse("example.com", 65536, "", true));
    Reject(() => Target.Parse("example.com", 443, "127.0.0.1", true));
});
Test("IPv6 accepted without sending IP SNI", () => {
    var t = Target.Parse("[::1]", 443, "", true); Equal(t.Host, "::1"); Equal(t.SendSni, false); Equal(t.Identity, "::1");
});
Test("KST conversion is independent of machine timezone", () => Equal(Dates.Kst(DateTimeOffset.Parse("2026-11-26T18:00:00Z")), "2026-11-27 03:00:00 KST"));
Test("D-day uses exact expiration instant and remaining full days", () => {
    var now = DateTimeOffset.Parse("2026-11-26T00:00:00Z");
    Equal(Dates.Dday(now.AddDays(90), now), "D-90");
    Equal(Dates.Dday(now.AddHours(23), now), "D-Day (24시간 미만)");
    Equal(Dates.Dday(now.AddSeconds(-1), now), "만료됨");
    Equal(Dates.Dday(now, now), "만료됨");
});
Test("Handshake completion is separate from certificate validation", () => {
    var r = new ProbeResult { HandshakeComplete = true, HostnameMatch = false, OsChainValid = true };
    Equal(r.ValidationSummary, "검증 실패");
    r.HandshakeComplete = false; Equal(r.ValidationSummary, "연결 미완료");
    r.HandshakeComplete = true; r.HostnameMatch = true; Equal(r.ValidationSummary, "검증 정상 · 폐기 미검사");
});
TlsTests.Run(Test);
StorageTests.Run(Test);
return failed == 0 ? 0 : 1;
