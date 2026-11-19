package notify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type DiscoveryClient struct {
	client *http.Client
}

func NewDiscoveryClient() *DiscoveryClient {
	return &DiscoveryClient{client: &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (c *DiscoveryClient) Send(ctx context.Context, target string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return errors.New("invalid discovery webhook request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return errors.New("discovery webhook request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discovery webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}
