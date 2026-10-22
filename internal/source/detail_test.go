package source

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/0x0034/sentinel/internal/model"
)

func detailFixture(t *testing.T) (string, model.Notice) {
	t.Helper()
	body, err := os.ReadFile("../../testdata/aliyun-detail.html")
	if err != nil {
		t.Fatal(err)
	}
	page, err := ParseHighRiskPage([]byte(highRiskSample(t)), 1)
	if err != nil {
		t.Fatal(err)
	}
	return string(body), page.Notices[0]
}

func TestDetailFieldsKeepScoringAndSoftwareSourcesSeparate(t *testing.T) {
	body, n := detailFixture(t)
	d, err := ParseDetail([]byte(body), n)
	if err != nil {
		t.Fatal(err)
	}
	if d.AliyunScore == nil || *d.AliyunScore != 9.7 || n.Vulnerability.CVSS != nil {
		t.Fatal("Aliyun score confused with CVSS")
	}
	if !strings.Contains(d.Description, "受影响版本") || strings.Contains(d.Description, "do-not-copy") || !strings.Contains(d.Solution, "\n重启服务") || !strings.Contains(d.Solution, "https://example.com/fix") {
		t.Fatalf("detail content lost: %+v", d)
	}
	for _, want := range []string{"厂商：example-vendor", "产品：example-server", "From (including) 1.0", "Up to (excluding) 2.0", "运行在以下环境", "版本：1.5"} {
		if !strings.Contains(d.AffectedSoftware, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(d.AffectedSoftware, "WAF") || strings.Contains(d.AffectedSoftware, "查看完整") {
		t.Fatal("coverage products or controls treated as affected software")
	}
	for _, score := range []string{"0", "N/A", "NaN", "Inf", "11", "-1"} {
		got, err := ParseDetail([]byte(strings.Replace(body, ">9.7<", ">"+score+"<", 1)), n)
		if err != nil {
			t.Fatal(err)
		}
		if score == "0" {
			if got.AliyunScore == nil || *got.AliyunScore != 0 {
				t.Fatal("zero score lost")
			}
		} else if got.AliyunScore != nil {
			t.Fatalf("invalid score %s accepted", score)
		}
	}
	d, err = ParseDetail([]byte(strings.Replace(body, "阿里云评分", "CVSS评分", 1)), n)
	if err != nil || d.AliyunScore != nil {
		t.Fatal("different scoring source accepted")
	}
}

func TestDetailRejectsWrongIdentityAndInvalidLayout(t *testing.T) {
	body, n := detailFixture(t)
	for name, bad := range map[string]string{
		"challenge":               "<html><script>challenge()</script></html>",
		"wrong identity":          strings.Replace(body, "<li>CVE-2020-10001</li>", "<li>CVE-2020-99999</li>", 1),
		"wrong title":             strings.Replace(body, "测试漏洞", "其他漏洞", 1),
		"missing description":     strings.Replace(body, "<h6>漏洞描述</h6>", "", 1),
		"duplicate section":       strings.Replace(body, "</body>", "<h6>解决建议</h6><div>other</div></body>", 1),
		"changed software header": strings.Replace(body, "<td>厂商</td>", "<td>防护产品</td>", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDetail([]byte(bad), n); err == nil {
				t.Fatal("invalid detail accepted")
			}
		})
	}
	called := false
	c := &Client{Browser: rendererFunc(func(context.Context, string) ([]byte, error) { called = true; return []byte(body), nil })}
	n.Link = "https://example.com/detail?id=" + n.ID
	if _, err := c.Detail(context.Background(), n); err == nil || called {
		t.Fatal("unsafe detail destination requested")
	}
}

func TestDetailFallbackUsesExplicitAffectedVersionAndPreservesMissing(t *testing.T) {
	body, n := detailFixture(t)
	start := strings.Index(body, "<h6>受影响软件情况")
	end := strings.Index(body, "<header class=")
	body = body[:start] + body[end:]
	d, err := ParseDetail([]byte(body), n)
	if err != nil || !strings.Contains(d.AffectedSoftware, "描述中的影响范围：\n受影响版本：测试组件 1.x。") {
		t.Fatalf("explicit description scope missing: %+v %v", d, err)
	}
	body = strings.Replace(body, "<p>受影响版本：测试组件 1.x。</p>", "", 1)
	d, err = ParseDetail([]byte(body), n)
	if err != nil || d.AffectedSoftware != "" {
		t.Fatal("affected versions invented")
	}
	body = strings.Replace(body, "<li>CVE-2020-10001</li>", "<li>AVD-2026-10001</li>", 1)
	n.Vulnerability.CVEID = ""
	if _, err := ParseDetail([]byte(body), n); err != nil {
		t.Fatalf("non-CVE record rejected: %v", err)
	}
}
