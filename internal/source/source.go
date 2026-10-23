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
	if !config.IsVulnerabilitySource(sub.Type) {
		return model.FetchResult{}, errors.New("unsupported source type")
	}
	listURL, parse := config.AliyunCVEURL, ParseCVEPage
	if sub.Type == config.AliyunHighRisk {
		listURL, parse = config.AliyunHighRiskURL, ParseHighRiskPage
	}
	if sub.URL != "" && sub.URL != listURL {
		return model.FetchResult{}, errors.New("Aliyun source URL must match its list type")
	}
	pages := sub.Pages
	if pages == 0 {
		pages = 5
	}
	if pages < 1 || pages > 20 {
		return model.FetchResult{}, errors.New("invalid Aliyun page limit")
	}
	var result model.FetchResult
	seen := map[string]model.Notice{}
	for number := 1; number <= pages; number++ {
		body, err := c.Browser.Render(ctx, fmt.Sprintf("%s?page=%d", listURL, number))
		if err != nil {
			return model.FetchResult{}, fmt.Errorf("Aliyun page %d: %w", number, err)
		}
		page, err := parse(body, number)
		if err != nil {
			return model.FetchResult{}, fmt.Errorf("Aliyun page %d: %w", number, err)
		}
		added := 0
		for _, n := range page.Notices {
			if previous, exists := seen[n.ID]; exists {
				if sub.Type != config.AliyunHighRisk || n.Title != previous.Title || n.Link != previous.Link || *n.Vulnerability != *previous.Vulnerability {
					return model.FetchResult{}, errors.New("Aliyun pages overlap or conflict; retry a complete scan")
				}
				result.Skipped++
				continue
			}
			seen[n.ID] = n
			added++
			result.Notices = append(result.Notices, n)
			if n.Vulnerability.DisclosureDate == "" {
				result.Undated++
			}
		}
		if len(page.Notices) > 0 && added == 0 {
			return model.FetchResult{}, errors.New("Aliyun page repeats previously scanned records")
		}
		if number >= page.TotalPages {
			break
		}
	}
	return result, nil
}
