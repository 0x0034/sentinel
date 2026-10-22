package source

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/0x0034/sentinel/internal/config"
)

func samplePage(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/aliyun-page.html")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCVEFieldsAndUnknowns(t *testing.T) {
	body := samplePage(t)
	page, err := ParseCVEPage([]byte(body), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Notices) != 2 || page.TotalPages != 2 || page.Undated != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}
	n := page.Notices[0]
	if n.ID != "AVD-2026-10001" || n.Vulnerability.CVEID != "CVE-2020-10001" || !strings.Contains(n.Link, "AVD-2026-10001") || n.Title != "测试漏洞 <组件>" {
		t.Fatalf("identity or title changed: %+v", n)
	}
	if n.PublishedAt != nil || n.Vulnerability.DisclosureDate != "2020-01-02" || n.Vulnerability.CVSS == nil || *n.Vulnerability.CVSS != 0 {
		t.Fatalf("incorrect date or zero score: %+v", n.Vulnerability)
	}
	unknown := page.Notices[1].Vulnerability
	if unknown.CVSS != nil || unknown.DisclosureDate != "" {
		t.Fatal("unknown values were invented")
	}
	for _, score := range []string{"NaN", "Inf", "-1", "11", "not a score"} {
		page, err := ParseCVEPage([]byte(strings.Replace(body, "<td>0.0</td>", "<td>"+score+"</td>", 1)), 1)
		if err != nil || page.Notices[0].Vulnerability.CVSS != nil {
			t.Fatalf("unreliable score %s accepted", score)
		}
	}
	missingCVE := strings.Replace(body, ">CVE-2020-10001<", ">N/A<", 1)
	page, err = ParseCVEPage([]byte(missingCVE), 1)
	if err != nil || page.Notices[0].ID != "AVD-2026-10001" || page.Notices[0].Vulnerability.CVEID != "" {
		t.Fatal("missing CVE lost valid AVD identity")
	}
}

func TestRejectIncompleteCVEPage(t *testing.T) {
	body := samplePage(t)
	for name, bad := range map[string]string{
		"challenge":          `<html><script>location.href='/captcha';</script></html>`,
		"wrong page":         strings.ReplaceAll(body, "第 1 页", "第 2 页"),
		"changed layout":     strings.Replace(body, "CVE编号", "编号", 1),
		"missing row column": strings.Replace(body, "<td>CWE-79</td>", "", 1),
		"bad detail host":    strings.Replace(body, "/detail?id=AVD-2026-10001", "https://example.com/detail?id=AVD-2026-10001", 1),
		"missing avd":        strings.Replace(body, "/detail?id=AVD-2026-10001", "/detail?id=CVE-2026-10001", 1),
		"duplicate id":       strings.ReplaceAll(body, "AVD-2026-10002", "AVD-2026-10001"),
		"unexpected empty":   `<span>第 1 页 / 1 页 • 总计 1 条记录</span><table><thead><tr><th>CVE编号</th><th>漏洞名称</th><th>漏洞类型</th><th>披露时间</th><th>CVSS评分</th></tr></thead><tbody></tbody></table>`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCVEPage([]byte(bad), 1); err == nil {
				t.Fatal("incomplete page accepted")
			}
		})
	}
	empty := `<span>第 1 页 / 1 页 • 总计 0 条记录</span><table><thead><tr><th>CVE编号</th><th>漏洞名称</th><th>漏洞类型</th><th>披露时间</th><th>CVSS评分</th></tr></thead><tbody><tr><td colspan="5">暂无数据</td></tr></tbody></table>`
	if p, err := ParseCVEPage([]byte(empty), 1); err != nil || len(p.Notices) != 0 {
		t.Fatalf("explicit empty rejected: %v", err)
	}
}

type rendererFunc func(context.Context, string) ([]byte, error)

func (f rendererFunc) Render(ctx context.Context, url string) ([]byte, error) { return f(ctx, url) }

func TestCompleteWindowOrNoResult(t *testing.T) {
	for _, kind := range []string{config.AliyunCVE, config.AliyunHighRisk} {
		t.Run(kind, func(t *testing.T) {
			first := samplePage(t)
			listURL := config.AliyunCVEURL
			if kind == config.AliyunHighRisk {
				first = highRiskSample(t)
				listURL = config.AliyunHighRiskURL
			}
			second := strings.NewReplacer("第 1 页", "第 2 页", "10001", "20001", "10002", "20002").Replace(first)
			for _, mode := range []string{"success", "failure", "overlap", "wrong page"} {
				t.Run(mode, func(t *testing.T) {
					calls := 0
					client := &Client{Browser: rendererFunc(func(ctx context.Context, url string) ([]byte, error) {
						calls++
						if !strings.HasPrefix(url, listURL+"?page=") {
							t.Fatalf("wrong source URL: %s", url)
						}
						if calls == 1 {
							return []byte(first), nil
						}
						if !strings.HasSuffix(url, "?page=2") {
							t.Fatal("wrong page URL")
						}
						switch mode {
						case "failure":
							return nil, errors.New("temporary fetch failure")
						case "overlap":
							return []byte(strings.Replace(first, "第 1 页", "第 2 页", 1)), nil
						case "wrong page":
							return []byte(first), nil
						default:
							return []byte(second), nil
						}
					})}
					result, err := client.Fetch(context.Background(), config.Subscription{Type: kind, Pages: 5})
					if mode == "success" {
						if err != nil || len(result.Notices) != 4 || calls != 2 {
							t.Fatalf("window or last page: %d %d %v", len(result.Notices), calls, err)
						}
					} else if err == nil || len(result.Notices) != 0 {
						t.Fatalf("partial scan exposed: %d %v", len(result.Notices), err)
					}
				})
			}
		})
	}
}
