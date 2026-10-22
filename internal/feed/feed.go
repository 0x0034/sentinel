package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/0x0034/sentinel/internal/model"
	"github.com/mmcdole/gofeed"
	"golang.org/x/net/html"
)

const MaxFeedBytes = 8 << 20

type Result struct {
	Notices          []model.Notice
	Skipped, Undated int
}

type Client struct{ HTTP *http.Client }

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("insecure redirect")
		}
		return nil
	}}}
}

func (c *Client) Fetch(ctx context.Context, source string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return Result{}, errors.New("invalid RSS request")
	}
	req.Header.Set("User-Agent", "Sentinel/0.1 RSS monitor")
	req.Header.Set("Accept", "application/rss+xml, application/atom+xml, application/xml, text/xml")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Result{}, errors.New("RSS request failed or timed out")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("RSS returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxFeedBytes+1))
	if err != nil || len(body) > MaxFeedBytes {
		return Result{}, errors.New("RSS response unreadable or larger than 8 MiB")
	}
	return Parse(string(body))
}

func Parse(body string) (Result, error) {
	f, err := gofeed.NewParser().ParseString(body)
	if err != nil {
		return Result{}, errors.New("invalid RSS or Atom document")
	}
	result := Result{}
	seen := map[string]bool{}
	for _, item := range f.Items {
		identity := strings.TrimSpace(item.GUID)
		if identity == "" {
			identity = strings.TrimSpace(item.Link)
		}
		if identity == "" {
			result.Skipped++
			continue
		}
		hash := sha256.Sum256([]byte(identity))
		id := hex.EncodeToString(hash[:])
		if seen[id] {
			continue
		}
		seen[id] = true
		link := strings.TrimSpace(item.Link)
		if u, e := url.Parse(link); e != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil {
			link = ""
		}
		content := item.Content
		if content == "" {
			content = item.Description
		}
		n := model.Notice{ID: id, Title: Plain(item.Title, 200), Link: link, Summary: Plain(content, 600), PublishedAt: item.PublishedParsed}
		if n.Title == "" {
			n.Title = "未命名公告"
		}
		if n.PublishedAt == nil {
			result.Undated++
		}
		result.Notices = append(result.Notices, n)
	}
	if len(f.Items) > 0 && len(result.Notices) == 0 {
		return result, errors.New("RSS contains no items with stable identities")
	}
	return result, nil
}

func Plain(raw string, maxRunes int) string {
	root, err := html.Parse(strings.NewReader(raw))
	if err != nil {
		return ""
	}
	var b strings.Builder
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style") {
			return
		}
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			b.WriteByte(' ')
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(root)
	runes := []rune(strings.Join(strings.Fields(b.String()), " "))
	if len(runes) > maxRunes {
		return string(runes[:maxRunes]) + "…"
	}
	return string(runes)
}
