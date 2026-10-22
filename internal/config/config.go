package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata"

	"gopkg.in/yaml.v3"
)

type Subscription struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	URL         string `yaml:"url"`
	WebhookEnv  string `yaml:"webhook_env"`
	Incremental bool   `yaml:"incremental"`
	Digest      bool   `yaml:"digest"`
	Webhook     string `yaml:"-"`
}

type Config struct {
	Database      string         `yaml:"database"`
	PollInterval  time.Duration  `yaml:"poll_interval"`
	DigestTime    string         `yaml:"digest_time"`
	Timezone      string         `yaml:"timezone"`
	Subscriptions []Subscription `yaml:"subscriptions"`
	Location      *time.Location `yaml:"-"`
	DigestHour    int            `yaml:"-"`
	DigestMinute  int            `yaml:"-"`
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, errors.New("cannot open configuration file")
	}
	defer f.Close()
	return Decode(f, os.Getenv)
}

func Decode(r io.Reader, getenv func(string) string) (Config, error) {
	c := Config{Database: "/data/sentinel.db", PollInterval: 5 * time.Minute, DigestTime: "09:00", Timezone: "Asia/Shanghai"}
	decoder := yaml.NewDecoder(io.LimitReader(r, 1<<20))
	decoder.KnownFields(true)
	if err := decoder.Decode(&c); err != nil {
		return c, errors.New("invalid YAML configuration or unknown fields")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return c, errors.New("configuration must contain one YAML document")
	}
	if strings.TrimSpace(c.Database) == "" {
		return c, errors.New("database path is required")
	}
	if c.PollInterval < time.Second || c.PollInterval > 24*time.Hour {
		return c, errors.New("poll_interval must be between 1s and 24h")
	}
	var err error
	c.Location, err = time.LoadLocation(c.Timezone)
	if err != nil {
		return c, errors.New("invalid timezone")
	}
	t, err := time.Parse("15:04", c.DigestTime)
	if err != nil {
		return c, errors.New("digest_time must use HH:MM")
	}
	c.DigestHour, c.DigestMinute = t.Hour(), t.Minute()
	if len(c.Subscriptions) == 0 {
		return c, errors.New("at least one subscription is required")
	}
	seen := map[string]bool{}
	for i := range c.Subscriptions {
		s := &c.Subscriptions[i]
		if !identifier.MatchString(s.ID) || seen[s.ID] {
			return c, fmt.Errorf("subscription %d has an invalid or duplicate id", i+1)
		}
		seen[s.ID] = true
		if strings.TrimSpace(s.Name) == "" {
			s.Name = s.ID
		}
		u, err := url.Parse(s.URL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Fragment != "" {
			return c, fmt.Errorf("subscription %s has an invalid RSS URL", s.ID)
		}
		if !s.Incremental && !s.Digest {
			return c, fmt.Errorf("subscription %s must enable incremental or digest", s.ID)
		}
		if !envName.MatchString(s.WebhookEnv) {
			return c, fmt.Errorf("subscription %s requires a webhook_env variable name", s.ID)
		}
		s.Webhook = getenv(s.WebhookEnv)
		if !ValidWebhook(s.Webhook) {
			return c, fmt.Errorf("subscription %s: webhook environment variable is missing or invalid", s.ID)
		}
	}
	return c, nil
}

func ValidWebhook(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host == "open.feishu.cn" && u.User == nil && u.RawQuery == "" && u.Fragment == "" && strings.HasPrefix(u.Path, "/open-apis/bot/v2/hook/") && len(strings.TrimPrefix(u.Path, "/open-apis/bot/v2/hook/")) > 0
}
