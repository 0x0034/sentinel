package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/0x0034/sentinel/internal/model"
)

const MaxPayloadBytes = 18 * 1024

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func card(title, intro string, notices []model.Notice, loc *time.Location) ([]byte, error) {
	elements := []any{map[string]any{"tag": "div", "text": map[string]string{"tag": "plain_text", "content": intro}}}
	for _, n := range notices {
		published := "发布时间未提供"
		if n.PublishedAt != nil {
			published = n.PublishedAt.In(loc).Format("2006-01-02 15:04 MST")
		}
		text := clip(n.Title, 200) + "\n" + published
		if v := n.Vulnerability; v != nil {
			score, disclosed, cve := "未知", "未提供", v.CVEID
			if v.CVSS != nil {
				score = strconv.FormatFloat(*v.CVSS, 'f', 1, 64)
			}
			if v.DisclosureDate != "" {
				disclosed = v.DisclosureDate
			}
			if cve == "" {
				cve = "未提供"
			}
			text = clip(n.Title, 200) + "\nCVE：" + clip(cve, 100) + "\nAVD：" + clip(v.AVDID, 120) + "\n漏洞类型：" + clip(v.Type, 120) + "\nCVSS：" + score + "\n披露日期：" + disclosed
			if !n.FirstSeen.IsZero() {
				text += "\n首次发现：" + n.FirstSeen.In(loc).Format("2006-01-02 15:04 MST")
			}
		}
		if n.Summary != "" {
			text += "\n" + clip(n.Summary, 600)
		}
		elements = append(elements, map[string]string{"tag": "hr"}, map[string]any{"tag": "div", "text": map[string]string{"tag": "plain_text", "content": text}})
		if n.Link != "" && len(n.Link) <= 2048 {
			elements = append(elements, map[string]any{"tag": "action", "actions": []any{map[string]any{"tag": "button", "text": map[string]string{"tag": "plain_text", "content": "查看原文"}, "url": n.Link, "type": "default"}}})
		}
	}
	return json.Marshal(map[string]any{"msg_type": "interactive", "card": map[string]any{"config": map[string]bool{"wide_screen_mode": true}, "header": map[string]any{"template": "red", "title": map[string]string{"tag": "plain_text", "content": title}}, "elements": elements}})
}

func Incremental(name string, notice model.Notice, loc *time.Location) ([]byte, error) {
	title, intro := " · 新公告", "订阅源发现新公告"
	if notice.Vulnerability != nil {
		title, intro = " · 新发现漏洞", "CVE 漏洞库中新发现的条目，不代表今天首次披露。"
	}
	body, err := card(clip(name, 80)+title, intro, []model.Notice{notice}, loc)
	if err == nil && len(body) > MaxPayloadBytes {
		return nil, errors.New("incremental card exceeds size limit")
	}
	return body, err
}

func Digest(name, date string, notices []model.Notice, loc *time.Location, degraded bool) ([][]byte, error) {
	return digest(name, date, notices, loc, degraded, false)
}
func VulnerabilityDigest(name, date string, notices []model.Notice, loc *time.Location, degraded bool) ([][]byte, error) {
	return digest(name, date, notices, loc, degraded, true)
}
func digest(name, date string, notices []model.Notice, loc *time.Location, degraded, vulnerabilities bool) ([][]byte, error) {
	zone := loc.String()
	if zone == "Asia/Shanghai" {
		zone = "北京时间"
	}
	intro := "汇总范围：" + date + "（" + zone + "）。仅包含已采集记录，来源窗口之外的公告可能未被采集。"
	empty, label := " 未采集到昨日公告。", " · 昨日汇总 · "
	if vulnerabilities {
		intro = "首次发现范围：" + date + "（" + zone + "）。排除初始化基线；只覆盖已扫描页面，未覆盖的漏洞可能未被发现。"
		empty, label = " 未发现昨日新增漏洞记录。", " · 昨日新发现 · "
	}
	if degraded {
		intro += " 本次订阅源抓取失败，内容可能不完整。"
	}
	if len(notices) == 0 {
		intro += empty
	}
	title := clip(name, 80) + label + date
	groups := [][]model.Notice{{}}
	for _, n := range notices {
		index := len(groups) - 1
		candidate := append(append([]model.Notice{}, groups[index]...), n)
		body, err := card(title, intro, candidate, loc)
		if err != nil {
			return nil, err
		}
		if len(body) > MaxPayloadBytes-128 {
			if len(groups[index]) == 0 {
				return nil, errors.New("notice exceeds card size limit")
			}
			groups = append(groups, []model.Notice{n})
		} else {
			groups[index] = candidate
		}
	}
	result := make([][]byte, 0, len(groups))
	for i, group := range groups {
		body, err := card(fmt.Sprintf("%s (%d/%d)", title, i+1, len(groups)), intro, group, loc)
		if err != nil {
			return nil, err
		}
		if len(body) > MaxPayloadBytes {
			return nil, errors.New("digest card exceeds size limit")
		}
		result = append(result, body)
	}
	return result, nil
}

type Client struct {
	HTTP        *http.Client
	MinInterval time.Duration
	mu          sync.Mutex
	next        map[string]time.Time
}

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, MinInterval: time.Second, next: map[string]time.Time{}}
}

func (c *Client) Send(ctx context.Context, webhook string, payload []byte) error {
	if len(payload) > MaxPayloadBytes {
		return errors.New("card exceeds request size limit")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.next == nil {
		c.next = map[string]time.Time{}
	}
	if delay := time.Until(c.next[webhook]); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.next[webhook] = time.Now().Add(c.MinInterval)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhook, bytes.NewReader(payload))
	if err != nil {
		return errors.New("invalid robot request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return errors.New("robot request failed or timed out; delivery may be uncertain")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("robot returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65537))
	if err != nil || len(body) > 65536 {
		return errors.New("invalid robot response")
	}
	var result struct {
		Code *int `json:"code"`
	}
	if json.Unmarshal(body, &result) != nil || result.Code == nil {
		return errors.New("robot response lacks a valid business code")
	}
	if *result.Code != 0 {
		return fmt.Errorf("robot rejected request with code %d", *result.Code)
	}
	return nil
}
