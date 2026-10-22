package source

import (
	"context"
	"errors"
	"fmt"

	"github.com/0x0034/sentinel/internal/config"
	"github.com/0x0034/sentinel/internal/feed"
	"github.com/0x0034/sentinel/internal/model"
)

type Renderer interface {
	Render(context.Context, string) ([]byte, error)
}

type Client struct {
	RSS     *feed.Client
	Browser Renderer
}

func NewClient(browser config.Browser) *Client {
	return &Client{RSS: feed.NewClient(), Browser: &Chromium{Binary: browser.Executable, NoSandbox: browser.NoSandbox, Timeout: browser.PageTimeout}}
}

func (c *Client) Fetch(ctx context.Context, sub config.Subscription) (model.FetchResult, error) {
	if sub.Type == "" || sub.Type == config.RSS {
		return c.RSS.Fetch(ctx, sub.URL)
	}
	if sub.Type != config.AliyunCVE {
		return model.FetchResult{}, errors.New("unsupported source type")
	}
	pages := sub.Pages
	if pages == 0 {
		pages = 5
	}
	if pages < 1 || pages > 20 {
		return model.FetchResult{}, errors.New("invalid CVE page limit")
	}
	var result model.FetchResult
	seen := map[string]bool{}
	for number := 1; number <= pages; number++ {
		body, err := c.Browser.Render(ctx, fmt.Sprintf("%s?page=%d", config.AliyunCVEURL, number))
		if err != nil {
			return model.FetchResult{}, fmt.Errorf("CVE page %d: %w", number, err)
		}
		page, err := ParseCVEPage(body, number)
		if err != nil {
			return model.FetchResult{}, fmt.Errorf("CVE page %d: %w", number, err)
		}
		for _, n := range page.Notices {
			if seen[n.ID] {
				return model.FetchResult{}, errors.New("CVE pages overlap; retry a complete scan")
			}
			seen[n.ID] = true
			result.Notices = append(result.Notices, n)
		}
		result.Undated += page.Undated
		if number >= page.TotalPages {
			break
		}
	}
	return result, nil
}
