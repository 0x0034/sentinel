package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0x0034/sentinel/internal/model"
)

const MaxPayloadBytes = 18 * 1024

// JSON 2.0 counts both components and nested text elements toward this limit.
const maxCardElements = 200

var errCardElements = errors.New("card exceeds element limit")

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func card(title, intro string, notices []model.Notice, loc *time.Location) ([]byte, error) {
	for limit := 1000; ; limit /= 2 {
		body, err := renderCard(title, intro, notices, loc, limit)
		if err != nil || len(notices) != 1 || len(body) <= MaxPayloadBytes-128 || limit <= 125 {
			return body, err
		}
	}
}

func renderCard(title, intro string, notices []model.Notice, loc *time.Location, detailLimit int) ([]byte, error) {
	introColor := "grey"
	if strings.Contains(intro, "抓取失败") {
		introColor = "red"
	}
	elements := []any{plainText(intro, "notation", introColor)}
	for i, n := range notices {
		if i > 0 {
			elements = append(elements, map[string]any{"tag": "hr"})
		}
		elements = append(elements, plainText(clip(n.Title, 200), "heading", "default"))
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
			description, solution, affected, aliyunScore := "详情暂未获取，请查看原文", "详情暂未获取，请查看原文", "详情暂未获取，请查看原文", "暂未获取"
			aliyunColor := "grey"
			if d := v.Details; d != nil {
				description, solution, affected = detailValue(d.Description, detailLimit), detailValue(d.Solution, detailLimit), detailValue(d.AffectedSoftware, detailLimit)
				aliyunScore = "来源未提供"
				if d.AliyunScore != nil {
					aliyunScore = strconv.FormatFloat(*d.AliyunScore, 'f', 1, 64) + " / 10"
					aliyunColor = "red"
				}
			}
			elements = append(elements, twoColumns(
				plainText("阿里云评分："+aliyunScore, "heading", aliyunColor),
				plainText("CVSS："+score, "normal", "default"),
			))
			identity := "AVD：" + clip(v.AVDID, 120) + "\nCVE：" + clip(cve, 100) + "\n漏洞类型：" + clip(v.Type, 120)
			timeline := "披露日期：" + clip(disclosed, 120)
			if v.Status != "" {
				timeline += "\n漏洞状态：" + clip(v.Status, 120)
			}
			if !n.FirstSeen.IsZero() {
				timeline += "\n首次发现：" + displayTime(n.FirstSeen, loc)
			}
			elements = append(elements, twoColumns(plainText(identity, "normal", "default"), plainText(timeline, "normal", "default")))
			elements = append(elements, detailSection("漏洞描述", description)...)
			elements = append(elements, detailSection("解决建议", solution)...)
			elements = append(elements, detailSection("受影响软件情况", affected)...)
		} else {
			published := "发布时间未提供"
			if n.PublishedAt != nil {
				published = "发布时间：" + displayTime(*n.PublishedAt, loc)
			}
			elements = append(elements, plainText(published, "notation", "grey"))
		}
		if n.Summary != "" {
			elements = append(elements, plainText(clip(n.Summary, 600), "normal", "default"))
		}
		if validCardLink(n.Link) {
			elements = append(elements, map[string]any{
				"tag": "button", "text": map[string]any{"tag": "plain_text", "content": "查看原文"},
				"type": "default", "size": "medium", "width": "fill",
				"behaviors": []any{map[string]any{"type": "open_url", "default_url": n.Link}},
			})
		}
	}
	card := map[string]any{
		"schema": "2.0",
		"config": map[string]any{"update_multi": true, "summary": map[string]any{"content": fmt.Sprintf("%s · %d 条", title, len(notices))}},
		"header": map[string]any{"template": "red", "title": map[string]any{"tag": "plain_text", "content": title}},
		"body":   map[string]any{"direction": "vertical", "padding": "12px", "vertical_spacing": "8px", "elements": elements},
	}
	if countCardElements(card) > maxCardElements {
		return nil, errCardElements
	}
	return json.Marshal(map[string]any{"msg_type": "interactive", "card": card})
}

func plainText(content, size, color string) map[string]any {
	return map[string]any{"tag": "div", "text": map[string]any{
		"tag": "plain_text", "content": content, "text_size": size, "text_color": color,
	}}
}

func twoColumns(left, right map[string]any) map[string]any {
	return map[string]any{"tag": "column_set", "flex_mode": "stretch", "horizontal_spacing": "12px", "columns": []any{
		map[string]any{"tag": "column", "width": "weighted", "weight": 1, "elements": []any{left}},
		map[string]any{"tag": "column", "width": "weighted", "weight": 1, "elements": []any{right}},
	}}
}

func detailSection(label, value string) []any {
	// Only application-owned labels are Markdown. Source text stays literal.
	return []any{
		map[string]any{"tag": "markdown", "content": "**" + label + "**", "margin": "8px 0px 0px 0px"},
		plainText(value, "normal", "default"),
	}
}

func displayTime(value time.Time, loc *time.Location) string {
	if loc.String() == "Asia/Shanghai" {
		return value.In(loc).Format("2006-01-02 15:04") + " 北京时间"
	}
	return value.In(loc).Format("2006-01-02 15:04 MST")
}

func validCardLink(value string) bool {
	u, err := url.ParseRequestURI(value)
	return len(value) <= 2048 && err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil
}

func countCardElements(value any) int {
	count := 0
	switch value := value.(type) {
	case map[string]any:
		if _, ok := value["tag"]; ok {
			count++
		}
		for _, child := range value {
			count += countCardElements(child)
		}
	case []any:
		for _, child := range value {
			count += countCardElements(child)
		}
	}
	return count
}

func detailValue(value string, limit int) string {
	if value == "" {
		return "来源未提供"
	}
	if len([]rune(value)) > limit {
		return clip(value, limit) + "（完整内容见原文）"
	}
	return value
}

func Incremental(name string, notice model.Notice, loc *time.Location) ([]byte, error) {
	title, intro := " · 新公告", "订阅源发现新公告"
	if notice.Vulnerability != nil {
		title, intro = " · 新发现漏洞", "漏洞库中新发现的条目，不代表今天首次披露。"
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
		if err != nil && !errors.Is(err, errCardElements) {
			return nil, err
		}
		if errors.Is(err, errCardElements) || len(body) > MaxPayloadBytes-128 {
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
