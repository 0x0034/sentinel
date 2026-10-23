package source

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/0x0034/sentinel/internal/config"
)

func highRiskSample(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/aliyun-high-risk-page.html")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestHighRiskSharedBoundaryDeduplicatesOnlyIdenticalRecords(t *testing.T) {
	first := highRiskSample(t)
	second := strings.NewReplacer("第 1 页", "第 2 页", "10002", "20002").Replace(first)
	for _, conflict := range []bool{false, true} {
		body := second
		if conflict {
			body = strings.Replace(body, "<span>PoC</span>", "<span>EXP</span>", 1)
		}
		client := &Client{Browser: rendererFunc(func(ctx context.Context, url string) ([]byte, error) {
			if strings.HasSuffix(url, "?page=2") {
				return []byte(body), nil
			}
			return []byte(first), nil
		})}
		result, err := client.Fetch(context.Background(), config.Subscription{Type: config.AliyunHighRisk, Pages: 5})
		if conflict {
			if err == nil || len(result.Notices) != 0 {
				t.Fatal("conflicting duplicate exposed partial results")
			}
		} else if err != nil || len(result.Notices) != 3 || result.Skipped != 1 || result.Notices[2].ID != "AVD-2026-20002" {
			t.Fatalf("identical boundary record not deduplicated: %+v %v", result, err)
		}
	}
}

func TestHighRiskFieldsWithoutInventingCVEOrScore(t *testing.T) {
	body := highRiskSample(t)
	p, err := ParseHighRiskPage([]byte(body), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Notices) != 2 || p.TotalPages != 2 || p.Undated != 1 {
		t.Fatalf("unexpected page: %+v", p)
	}
	v := p.Notices[0].Vulnerability
	if p.Notices[0].ID != "AVD-2026-10001" || v.CVEID != "CVE-2020-10001" || v.Status != "CVE PoC" || v.CVSS != nil || v.DisclosureDate != "2020-01-02" {
		t.Fatalf("incorrect fields: %+v", v)
	}
	v = p.Notices[1].Vulnerability
	if v.CVEID != "" || v.CVSS != nil || v.DisclosureDate != "" || v.Status != "EXP 武器化" {
		t.Fatalf("invented fields: %+v", v)
	}
	multiple := strings.Replace(body, "（CVE-2020-10001）", "（CVE-2020-10001、CVE-2020-10002、CVE-2020-10001）", 1)
	p, err = ParseHighRiskPage([]byte(multiple), 1)
	if err != nil || p.Notices[0].Vulnerability.CVEID != "CVE-2020-10001, CVE-2020-10002" {
		t.Fatalf("explicit title identifiers lost: %+v %v", p, err)
	}
}

func TestRejectInvalidHighRiskPages(t *testing.T) {
	body := highRiskSample(t)
	for name, bad := range map[string]string{
		"CVE list":            samplePage(t),
		"challenge":           `<html><script>location.href='/captcha'</script></html>`,
		"mismatched identity": strings.Replace(body, ">AVD-2026-10001<", ">AVD-2026-99999<", 1),
		"wrong page":          strings.ReplaceAll(body, "第 1 页", "第 2 页"),
		"changed layout":      strings.Replace(body, "漏洞状态", "CVSS评分", 1),
		"missing column":      strings.Replace(body, "<td>CWE-79</td>", "", 1),
		"duplicate":           strings.ReplaceAll(body, "10002", "10001"),
		"external link":       strings.Replace(body, "/detail?id=AVD-2026-10001", "https://example.com/detail?id=AVD-2026-10001", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseHighRiskPage([]byte(bad), 1); err == nil {
				t.Fatal("invalid page accepted")
			}
		})
	}
	if _, err := ParseCVEPage([]byte(body), 1); err == nil {
		t.Fatal("CVE parser accepted high-risk list")
	}
}
