package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x0034/sentinel/internal/model"
)

func TestRedCardsAndChunking(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	published := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	var notices []model.Notice
	for i := 0; i < 100; i++ {
		notices = append(notices, model.Notice{Title: fmt.Sprintf("UNIQUE-%03d", i), Summary: strings.Repeat("中<&", 600), Link: "https://example.com/notice", PublishedAt: &published})
	}
	cards, err := Digest("公告", "2026-10-21", notices, loc, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) < 2 {
		t.Fatal("large digest was not split")
	}
	var combined strings.Builder
	for _, body := range cards {
		if len(body) > MaxPayloadBytes {
			t.Fatalf("oversized: %d", len(body))
		}
		var card struct {
			Card struct {
				Header struct {
					Template string `json:"template"`
				} `json:"header"`
			} `json:"card"`
		}
		if err := json.Unmarshal(body, &card); err != nil {
			t.Fatal(err)
		}
		if card.Card.Header.Template != "red" {
			t.Fatal("non-red card")
		}
		combined.Write(body)
	}
	for i := 0; i < 100; i++ {
		if strings.Count(combined.String(), fmt.Sprintf("UNIQUE-%03d", i)) != 1 {
			t.Fatalf("missing or duplicate notice %d", i)
		}
	}
	empty, err := Digest("公告", "2026-10-21", nil, loc, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(empty[0]), "未采集到昨日公告") || !strings.Contains(string(empty[0]), "抓取失败") {
		t.Fatal("empty or degraded coverage not explained")
	}
}

func TestBusinessResponse(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		ok         bool
	}{
		{"success", `{"code":0}`, 200, true}, {"business error", `{"code":19024,"msg":"private-secret"}`, 200, false},
		{"missing", `{}`, 200, false}, {"legacy", `{"StatusCode":0}`, 200, false}, {"null", `{"code":null}`, 200, false},
		{"malformed", "html", 200, false}, {"HTTP error", `{"code":0}`, 500, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer srv.Close()
			c := NewClient()
			c.MinInterval = 0
			err := c.Send(context.Background(), srv.URL, []byte(`{}`))
			if (err == nil) != tc.ok {
				t.Fatalf("unexpected result: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "private-secret") {
				t.Fatal("response leaked")
			}
		})
	}
}

func TestSharedTargetThrottleAndRedirect(t *testing.T) {
	var mu sync.Mutex
	var received []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		received = append(received, time.Now())
		mu.Unlock()
		fmt.Fprint(w, `{"code":0}`)
	}))
	defer srv.Close()
	c := NewClient()
	c.MinInterval = 40 * time.Millisecond
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Send(context.Background(), srv.URL, []byte(`{}`)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	snapshot := append([]time.Time{}, received...)
	mu.Unlock()
	if len(snapshot) != 3 {
		t.Fatalf("received %d", len(snapshot))
	}
	for i := 1; i < len(snapshot); i++ {
		if snapshot[i].Sub(snapshot[i-1]) < 35*time.Millisecond {
			t.Fatal("shared target exceeded rate")
		}
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, srv.URL, 307) }))
	defer redirect.Close()
	if err := c.Send(context.Background(), redirect.URL, []byte(`{}`)); err == nil {
		t.Fatal("webhook redirect followed")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 3 {
		t.Fatal("webhook payload reached redirected destination")
	}
}
