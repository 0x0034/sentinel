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
