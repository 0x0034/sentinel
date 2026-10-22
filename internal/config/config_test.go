package config

import (
	"strings"
	"testing"
	"time"
)

const valid = `subscriptions:
  - id: sample
    url: https://example.com/feed
    webhook_env: BOT
    incremental: true
    digest: true
`

func TestConfiguration(t *testing.T) {
	lookup := func(string) string { return "https://open.feishu.cn/open-apis/bot/v2/hook/test-placeholder" }
	c, err := Decode(strings.NewReader(valid), lookup)
	if err != nil {
		t.Fatal(err)
	}
	if c.PollInterval != 5*time.Minute || c.DigestHour != 9 || c.Location.String() != "Asia/Shanghai" {
		t.Fatalf("wrong defaults: %+v", c)
	}
	for name, body := range map[string]string{
		"unknown":   "unexpected: secret-value\n" + valid,
		"interval":  "poll_interval: 0s\n" + valid,
		"timezone":  "timezone: impossible\n" + valid,
		"time":      "digest_time: 25:00\n" + valid,
		"scheme":    strings.Replace(valid, "https://example.com/feed", "file:///secret-value", 1),
		"modes":     strings.ReplaceAll(valid, ": true", ": false"),
		"documents": valid + "---\n" + valid,
		"duplicate": valid + strings.TrimPrefix(valid, "subscriptions:\n"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Decode(strings.NewReader(body), lookup)
			if err == nil {
				t.Fatal("expected rejection")
			}
			if strings.Contains(err.Error(), "secret-value") {
				t.Fatal("error leaked configuration")
			}
		})
	}
	_, err = Decode(strings.NewReader(valid), func(string) string { return "https://attacker.invalid/secret-value" })
	if err == nil || strings.Contains(err.Error(), "secret-value") {
		t.Fatal("invalid webhook must be rejected without leaking")
	}
}

func TestSourceConfigurationAndLegacyDefaults(t *testing.T) {
	lookup := func(string) string { return "https://open.feishu.cn/open-apis/bot/v2/hook/test-placeholder" }
	legacy, err := Decode(strings.NewReader(valid), lookup)
	if err != nil || legacy.Subscriptions[0].Type != RSS || legacy.Subscriptions[0].Pages != 0 {
		t.Fatal("legacy RSS configuration changed")
	}
	cve := strings.Replace(valid, "url: https://example.com/feed", "type: aliyun_cve", 1)
	c, err := Decode(strings.NewReader(cve), lookup)
	if err != nil || c.Subscriptions[0].URL != AliyunCVEURL || c.Subscriptions[0].Pages != 5 || c.Browser.PageTimeout != 45*time.Second {
		t.Fatalf("CVE defaults: %+v %v", c, err)
	}
	for _, bad := range []string{
		strings.Replace(cve, "type: aliyun_cve", "type: unsupported", 1),
		strings.Replace(cve, "type: aliyun_cve", "type: aliyun_cve\n    pages: -1", 1),
		strings.Replace(cve, "type: aliyun_cve", "type: aliyun_cve\n    pages: 21", 1),
		strings.Replace(cve, "type: aliyun_cve", "type: aliyun_cve\n    url: https://example.com", 1),
		strings.Replace(valid, "url:", "pages: 5\n    url:", 1),
		"browser:\n  page_timeout: 3m\n" + cve,
	} {
		if _, err := Decode(strings.NewReader(bad), lookup); err == nil {
			t.Fatal("invalid source configuration accepted")
		}
	}
}
