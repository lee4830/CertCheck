using CertificateChecker;
namespace CertificateChecker.Gui;

sealed class CertificateView : UserControl
{
    readonly ListBox items = new() { Dock = DockStyle.Fill, IntegralHeight = false, HorizontalScrollbar = true };
    readonly TextBox detail = new() { Dock = DockStyle.Fill, Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, BorderStyle = BorderStyle.None, BackColor = Color.White };
    readonly Label caption = new() { Dock = DockStyle.Top, Height = 60, Padding = new Padding(10), BackColor = Color.FromArgb(237, 244, 252) };
    List<CertificateInfo> certificates = [];
    public CertificateInfo? Selected => items.SelectedIndex >= 0 && items.SelectedIndex < certificates.Count ? certificates[items.SelectedIndex] : null;
    public CertificateView(string explanation)
    {
        Dock = DockStyle.Fill;
        caption.Text = explanation;
        var split = new SplitContainer { Dock = DockStyle.Fill, SplitterDistance = 300, Size = new Size(1000, 400), Panel1MinSize = 180, Panel2MinSize = 250 };
        split.Panel1.Controls.Add(items); split.Panel2.Padding = new Padding(12); split.Panel2.Controls.Add(detail);
        Controls.Add(split); Controls.Add(caption);
        items.SelectedIndexChanged += (_, _) => ShowCertificate();
    }
    public void SetCertificates(List<CertificateInfo> value)
    {
        certificates = value;
        items.Items.Clear(); detail.Clear();
        for (int i = 0; i < value.Count; i++) items.Items.Add($"{i + 1:00}  {value[i].Subject}");
        if (value.Count > 0) items.SelectedIndex = 0;
        else detail.Text = "수집된 인증서가 없습니다. 결과 탭에서 연결 오류를 확인하세요.";
    }
    void ShowCertificate()
    {
        if (Selected is not { } c) return;
        detail.Text = string.Join(Environment.NewLine, new[] {
            "주체 (Subject)", c.Subject, "", "발급자 (Issuer)", c.Issuer, "",
            $"유효 시작  {Dates.Kst(c.NotBeforeUtc)}", $"만료 일시  {Dates.Kst(c.NotAfterUtc)}", "",
            $"일련번호  {c.Serial}", $"서명 알고리즘  {c.Signature}", "", "SHA-256 지문", c.Sha256, "",
            "주체 대체 이름 (SAN)", c.San.Length == 0 ? "SAN 없음" : c.San, "",
            "OS 체인 요소 상태", string.IsNullOrEmpty(c.Status) ? "오류 없음 또는 이 목록에서는 검증하지 않음 (결과 탭 참조)" : c.Status
        });
    }
}
