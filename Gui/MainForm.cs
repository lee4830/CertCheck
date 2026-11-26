using CertificateChecker;

namespace CertificateChecker.Gui;

sealed class MainForm : Form
{
    static readonly Color Ink = Color.FromArgb(24, 43, 69);
    static readonly Color Blue = Color.FromArgb(30, 91, 174);
    readonly TextBox host = new() { Text = "example.com", Dock = DockStyle.Fill, AccessibleName = "서버 도메인 또는 IP" };
    readonly NumericUpDown port = new() { Minimum = 1, Maximum = 65535, Value = 443, Dock = DockStyle.Fill, AccessibleName = "포트" };
    readonly TextBox sni = new() { PlaceholderText = "비우면 접속 도메인 사용", Dock = DockStyle.Fill, AccessibleName = "TLS SNI 및 검증 이름" };
    readonly NumericUpDown timeout = new() { Minimum = 1, Maximum = 60, Value = 15, Dock = DockStyle.Fill, AccessibleName = "제한 시간 초" };
    readonly CheckBox sendSni = new() { Text = "TLS SNI 전송", Checked = true, AutoSize = true };
    readonly CheckBox revocation = new() { Text = "온라인 폐기 검사 (추가 통신)", AutoSize = true };
    readonly Button query = new() { Text = "인증서 조회", Dock = DockStyle.Fill, BackColor = Blue, ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
    readonly Button cancel = new() { Text = "취소", AutoSize = true, Enabled = false };
    readonly Button copy = new() { Text = "결과 복사", AutoSize = true, Enabled = false };
    readonly Button export = new() { Text = "내보내기…", AutoSize = true, Enabled = false };
    readonly Label dday = new() { Text = "—", Dock = DockStyle.Fill, Font = new Font("맑은 고딕", 28, FontStyle.Bold), TextAlign = ContentAlignment.MiddleLeft };
    readonly Label summary = new() { Text = "도메인과 포트를 입력하고 조회하세요.", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, AutoEllipsis = true };
    readonly Label status = new() { Text = "준비 · 직접 TLS 연결 / Windows 11 x64", Dock = DockStyle.Fill, ForeColor = Color.DimGray, AutoEllipsis = true };
    readonly TextBox report = ReadBox();
    readonly TextBox dns = ReadBox();
    readonly TabControl tabs = new() { Dock = DockStyle.Fill };
    readonly CertificateView wire = new("실제 서버 전송 체인 · 동일 TLS 연결의 Certificate 메시지에서 받은 순서입니다.\n루트 인증서는 보통 전송되지 않습니다. 이 목록 자체는 신뢰 검증 결과가 아닙니다.");
    readonly CertificateView os = new("Windows OS 검증 체인 · 수신한 중간 인증서와 Windows 저장소/캐시를 이용해 구성합니다.\nAIA 다운로드는 비활성입니다. 서버가 보낸 목록과 개수·순서가 다를 수 있습니다.");
    readonly ListView history = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false };
    readonly HistoryStore store = new(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SSLCertificateChecker", "history.json"));
    readonly Panel inputs = new() { Dock = DockStyle.Fill };
    CancellationTokenSource? running;
    ProbeResult? current;
    bool closing;

    public MainForm()
    {
        Text = "SSL Certificate Checker 1.0"; StartPosition = FormStartPosition.CenterScreen;
        Size = new Size(1220, 890); MinimumSize = new Size(1060, 740);
        Font = new Font("맑은 고딕", 10); ForeColor = Ink; BackColor = Color.FromArgb(245, 247, 251);
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 6, Padding = new Padding(20) };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        foreach (var h in new[] { 78, 132, 100 }) root.RowStyles.Add(new RowStyle(SizeType.Absolute, h));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); root.RowStyles.Add(new RowStyle(SizeType.Absolute, 49)); root.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        Controls.Add(root);
        var header = new Panel { Dock = DockStyle.Fill, BackColor = Ink, Padding = new Padding(15, 8, 10, 5) };
        header.Controls.Add(new Label { Text = "SSL Certificate Checker", Dock = DockStyle.Top, Height = 34, ForeColor = Color.White, Font = new Font("Segoe UI", 20, FontStyle.Bold) });
        header.Controls.Add(new Label { Text = "인증서 만료 · TLS 연결 · 서버 전송 체인과 Windows 검증 체인", Dock = DockStyle.Bottom, Height = 24, ForeColor = Color.FromArgb(199, 218, 242) });
        root.Controls.Add(header, 0, 0);
        var grid = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 5, RowCount = 3, Padding = new Padding(0, 12, 0, 0) };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 46)); grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 54)); grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 96)); grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 132));
        grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 26)); grid.RowStyles.Add(new RowStyle(SizeType.Absolute, 36)); grid.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var labels = new[] { "서버 도메인 / IP", "포트", "SNI / 검증 이름 (선택)", "제한 시간(초)", "" };
        var fields = new Control[] { host, port, sni, timeout, query };
        for (int i = 0; i < fields.Length; i++) { grid.Controls.Add(new Label { Text = labels[i], Dock = DockStyle.Fill }, i, 0); fields[i].Margin = new Padding(0, 0, 10, 2); grid.Controls.Add(fields[i], i, 1); }
        var options = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false, Padding = new Padding(0, 5, 0, 0) };
        options.Controls.AddRange([sendSni, revocation, new Label { Text = "IP는 SNI 생략 · SAN으로 이름 검증", AutoSize = true, ForeColor = Color.DimGray, Padding = new Padding(8, 3, 0, 0) }]);
        grid.Controls.Add(options, 0, 2); grid.SetColumnSpan(options, 5); inputs.Controls.Add(grid); root.Controls.Add(inputs, 0, 1);
        var card = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = Color.White, Padding = new Padding(15, 4, 15, 4), ColumnCount = 2 };
        card.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 300)); card.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); card.Controls.Add(dday, 0, 0); card.Controls.Add(summary, 1, 0); root.Controls.Add(card, 0, 2);
        AddTab("조회 결과", report); AddTab("실제 서버 전송 체인", wire); AddTab("Windows 검증 체인", os); AddTab("DNS / 접속 정보", dns);
        var hp = new Panel { Dock = DockStyle.Fill };
        history.Columns.Add("조회 시각 (KST)", 175); history.Columns.Add("서버", 235); history.Columns.Add("검증 이름 / SNI", 250); history.Columns.Add("결과", 210);
        var hb = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 45, Padding = new Padding(5), WrapContents = false };
        var open = new Button { Text = "저장 결과 열기", AutoSize = true }; var apply = new Button { Text = "입력에 적용", AutoSize = true }; var clear = new Button { Text = "이력 전체 삭제", AutoSize = true };
        hb.Controls.AddRange([open, apply, clear]); hp.Controls.Add(history); hp.Controls.Add(hb); AddTab("조회 이력 (최근 50개)", hp);
        root.Controls.Add(tabs, 0, 3);
        var footer = new FlowLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(0, 8, 0, 0), WrapContents = false };
        footer.Controls.AddRange([copy, export, cancel, new Label { Text = "이력은 이 PC에 저장됩니다. 폐기 검사는 기본적으로 수행하지 않습니다.", AutoSize = true, Padding = new Padding(12, 5, 0, 0), ForeColor = Color.DimGray }]);
        root.Controls.Add(footer, 0, 4); root.Controls.Add(status, 0, 5);
        AcceptButton = query;
        query.Click += async (_, _) => await Query(); cancel.Click += (_, _) => { running?.Cancel(); status.Text = "취소 요청됨 · 진행 중인 Windows 검증은 완료 후 결과를 표시합니다."; };
        copy.Click += (_, _) => Guard(() => { if (current is not null) { Clipboard.SetText(current.Report()); status.Text = "표시 중인 결과를 클립보드에 복사했습니다."; } });
        export.Click += (_, _) => Guard(Export);
        open.Click += (_, _) => Guard(OpenHistory); history.DoubleClick += (_, _) => Guard(OpenHistory);
        apply.Click += (_, _) => { if (SelectedHistory() is { } r && running is null) { Apply(r.Target); tabs.SelectedIndex = 0; status.Text = "이력의 접속 정보를 입력했습니다. 조회를 누르면 새로 연결합니다."; } };
        clear.Click += (_, _) => Guard(() => { store.Clear(); RefreshHistory(); status.Text = "이력을 삭제했습니다."; });
        FormClosing += (_, _) => { closing = true; running?.Cancel(); };
        RefreshHistory();
    }
    static TextBox ReadBox() => new() { Multiline = true, ReadOnly = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Both, WordWrap = false, BackColor = Color.White, BorderStyle = BorderStyle.None };
    void AddTab(string title, Control control) { var page = new TabPage(title) { Padding = new Padding(10), BackColor = Color.White }; page.Controls.Add(control); tabs.TabPages.Add(page); }
    async Task Query()
    {
        Target target;
        try { target = Target.Parse(host.Text, (int)port.Value, sni.Text, sendSni.Checked, (int)timeout.Value, revocation.Checked); }
        catch (ArgumentException e) { MessageBox.Show(this, e.Message, "입력 확인", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        using var cts = new CancellationTokenSource(); running = cts;
        inputs.Enabled = false; cancel.Enabled = true; copy.Enabled = export.Enabled = false; current = null;
        wire.SetCertificates([]); os.SetCertificates([]); report.Clear(); dns.Clear();
        dday.Text = "조회 중"; dday.ForeColor = Blue; summary.Text = $"{target.Host}:{target.Port}\nDNS 확인 → TCP 연결 → TLS 인증서 수집 → Windows 검증";
        status.Text = "조회 중… DNS/TCP/TLS에 제한 시간을 적용합니다. OS 폐기 검사는 추가 시간이 걸릴 수 있습니다."; tabs.SelectedIndex = 0;
        try {
            var result = await Probe.QueryAsync(target, cts.Token);
            if (closing) return;
            Display(result);
            try { store.Add(result); RefreshHistory(); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { status.Text = $"결과 조회 완료 · 이력 저장 실패: {e.Message}"; }
        } catch (Exception e) { if (!closing) { dday.Text = "오류"; summary.Text = e.Message; status.Text = "조회 처리 실패"; } }
        finally { running = null; if (!closing) { inputs.Enabled = true; cancel.Enabled = false; } }
    }
    void Display(ProbeResult result)
    {
        current = result; report.Text = result.Report().ReplaceLineEndings(Environment.NewLine);
        wire.SetCertificates(result.ServerChain); os.SetCertificates(result.OsChain);
        var leaf = result.ServerChain.FirstOrDefault();
        bool trusted = result.HandshakeComplete && result.HostnameMatch == true && result.OsChainValid == true;
        string validation = result.ValidationSummary;
        if (leaf is null) { dday.Text = "조회 실패"; dday.ForeColor = Color.Firebrick; }
        else {
            dday.Text = Dates.Dday(leaf.NotAfterUtc, result.CheckedUtc);
            dday.Font = new Font("맑은 고딕", dday.Text.Length > 10 ? 18 : 28, FontStyle.Bold);
            double days = (leaf.NotAfterUtc - result.CheckedUtc).TotalDays;
            dday.ForeColor = !trusted || days <= 7 ? Color.Firebrick : days <= 30 ? Color.FromArgb(180, 101, 0) : Color.FromArgb(24, 118, 85);
        }
        summary.Text = $"{validation}  |  {result.Target.Host}:{result.Target.Port}\n" + (leaf is null ? result.Error : $"만료: {Dates.Kst(leaf.NotAfterUtc)}\n{result.TlsVersion}  ·  실제 접속: {result.RemoteEndpoint}");
        dns.Text = string.Join(Environment.NewLine, new[] { $"조회 시각: {Dates.Kst(result.CheckedUtc)}", $"접속 이름: {result.Target.Host}", $"포트: {result.Target.Port}", $"검증 이름: {result.Target.Identity}", $"SNI: {(result.Target.SendSni ? result.Target.Identity : "전송 안 함")}", "", "DNS 응답 후보 (모든 IP에 연결한 것은 아닙니다)", string.Join(Environment.NewLine, result.DnsAddresses), "", $"실제 접속 주소: {result.RemoteEndpoint}", $"TLS: {result.TlsVersion} / Cipher suite: {result.CipherSuite}", "", "직접 TLS만 지원합니다. HTTP 프록시, STARTTLS, 클라이언트 인증서는 지원하지 않습니다.", "DNS 조회와 TLS 연결은 사용 중인 네트워크의 영향을 받습니다." });
        copy.Enabled = export.Enabled = true;
        status.Text = $"{Dates.Kst(result.CheckedUtc)} 기준 저장 결과 · {validation}";
    }
    void Export()
    {
        if (current is null) return;
        using var dialog = new SaveFileDialog { Title = "표시 중인 조회 결과 내보내기", FileName = "certificate-result", AddExtension = true,
            InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Filter = "조회 결과 JSON|*.json|조회 결과 텍스트|*.txt|실제 서버 전송 체인 PEM|*.pem|선택 인증서 DER (CER)|*.cer" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        var cert = tabs.SelectedIndex == 2 ? os.Selected : tabs.SelectedIndex == 1 ? wire.Selected : current.ServerChain.FirstOrDefault();
        Exports.Save(current, (ExportFormat)(dialog.FilterIndex - 1), dialog.FileName, cert);
        status.Text = $"내보냈습니다: {dialog.FileName}";
    }
    void RefreshHistory()
    {
        history.Items.Clear();
        foreach (var r in store.Read()) {
            var item = new ListViewItem(Dates.Kst(r.CheckedUtc)) { Tag = r };
            item.SubItems.Add($"{r.Target.Host}:{r.Target.Port}"); item.SubItems.Add(r.Target.Identity + (r.Target.SendSni ? " / 전송" : " / 생략"));
            item.SubItems.Add(r.Error.Length > 0 ? "연결 오류" : r.OsChainValid == true && r.HostnameMatch == true ? "검증 정상" : "검증 실패"); history.Items.Add(item);
        }
        if (store.Warning is { } warning) status.Text = warning;
    }
    ProbeResult? SelectedHistory() => history.SelectedItems.Count == 0 ? null : history.SelectedItems[0].Tag as ProbeResult;
    void OpenHistory() { if (running is null && SelectedHistory() is { } result) { Display(result); Apply(result.Target); tabs.SelectedIndex = 0; } }
    void Apply(Target target) { host.Text = target.Host; port.Value = target.Port; sni.Text = target.Identity == target.Host ? "" : target.Identity; sendSni.Checked = target.SendSni; timeout.Value = target.TimeoutSeconds; revocation.Checked = target.OnlineRevocation; }
    void Guard(Action action) { try { action(); } catch (Exception e) { MessageBox.Show(this, e.Message, "작업 실패", MessageBoxButtons.OK, MessageBoxIcon.Warning); } }
}
