package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/0x0034/sentinel/internal/config"
	"github.com/0x0034/sentinel/internal/model"
	"github.com/0x0034/sentinel/internal/store"
)

func TestDiscoveryOnlySubscription(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	for _, flags := range []string{"", "    incremental: true\n    digest: true\n"} {
		c, err := config.Decode(strings.NewReader("subscriptions:\n  - id: sample\n    type: aliyun_high_risk\n    discovery_webhook_url: "+server.URL+"\n"+flags), func(string) string {
			t.Fatal("callback-only subscription read a credential")
			return ""
		})
		if err != nil {
			t.Fatal(err)
		}
		db, err := store.Open(filepath.Join(t.TempDir(), "discovery.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		feed, feishu := &fakeFeed{}, &captureSender{}
		a := New(c, db, feed, feishu, quiet())
		ctx := context.Background()
		now := time.Date(2026, 11, 19, 10, 0, 0, 0, c.Location)
		a.Now = func() time.Time { return now }
		if err := a.Once(ctx, now); err != nil {
			t.Fatal(err)
		}
		// Simulate a Feishu task left over from a previous configuration.
		if err := db.EnqueueDigest(ctx, "sample", "2026-11-17", [][]byte{[]byte("old card")}, now); err != nil {
			t.Fatal(err)
		}
		feed.result.Notices = []model.Notice{{ID: "AVD-1", Vulnerability: &model.Vulnerability{AVDID: "AVD-1"}}}
		before := received.Load()
		if err := a.Once(ctx, now); err != nil {
			t.Fatal(err)
		}
		pending, err := db.Pending(ctx, now)
		if err != nil || len(pending) != 1 || string(pending[0].Payload) != "old card" || pending[0].Attempts != 0 {
			t.Fatal("unexpected Feishu queue state")
		}
		if received.Load() != before+1 || len(feishu.bodies) != 0 {
			t.Fatal("expected only one discovery callback")
		}
	}
}

func TestDiscoveryWebhookPauseSwitchAndResumeAfterRestart(t *testing.T) {
	type request struct{ path, body string }
	requests := make(chan request, 16)
	var redirected atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Error("unexpected discovery request")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		requests <- request{r.URL.Path, string(body)}
		if r.URL.Path == "/original" && !redirected.Swap(true) {
			// A redirect is a failed delivery, even when the other endpoint accepts POST.
			http.Redirect(w, r, "/redirected", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	c := testConfig()
	sub := &c.Subscriptions[0]
	sub.Type, sub.Digest = config.AliyunHighRisk, false
	sub.DiscoveryWebhookURL = server.URL + "/original"
	path := filepath.Join(t.TempDir(), "callbacks.db")
	open := func() *store.Store {
		db, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		return db
	}
	db := open()
	feed, feishu := &fakeFeed{}, &captureSender{}
	a := New(c, db, feed, feishu, quiet())
	ctx := context.Background()
	now := time.Date(2026, 11, 19, 3, 0, 0, 0, time.UTC)
	poll := func(id, title string) {
		v := &model.Vulnerability{AVDID: id, CVEID: "CVE-2026-10000"}
		feed.result.Notices = []model.Notice{{ID: id, Title: title, Link: "https://example.org/detail", Vulnerability: v}}
		now = now.Add(time.Minute)
		a.Now = func() time.Time { return now }
		if err := a.Once(ctx, now); err != nil {
			t.Fatal(err)
		}
	}
	next := func(path string) string {
		t.Helper()
		select {
		case req := <-requests:
			if req.path != path {
				t.Fatalf("got request to %s, want %s", req.path, path)
			}
			return req.body
		default:
			t.Fatalf("missing request to %s", path)
			return ""
		}
	}
	poll("AVD-1", "baseline")
	if len(requests) != 0 || len(feishu.bodies) != 0 {
		t.Fatal("baseline delivered")
	}
	poll("AVD-2", "first discovery")
	first := next("/original")
	var event map[string]any
	if err := json.Unmarshal([]byte(first), &event); err != nil {
		t.Fatal(err)
	}
	if event["event_id"] == "" || event["event_id"] == nil || event["subscription_id"] != sub.ID || event["source"] != sub.Type || event["first_seen"] != now.Format(time.RFC3339) || event["avd_id"] != "AVD-2" || event["cve_id"] != "CVE-2026-10000" || event["title"] != "first discovery" || event["url"] != "https://example.org/detail" {
		t.Fatalf("wrong discovery payload: %s", first)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = open()
	defer db.Close()
	a = New(c, db, feed, feishu, quiet())
	sub.DiscoveryWebhookURL = ""
	poll("AVD-3", "while disabled")
	sub.DiscoveryWebhookURL = server.URL + "/new"
	poll("AVD-3", "edited")
	if len(requests) != 0 {
		t.Fatal("paused or disabled-period event leaked to a different target")
	}
	poll("AVD-4", "after switch")
	next("/new")
	poll("AVD-4", "edited after success")
	sub.DiscoveryWebhookURL = server.URL + "/original"
	poll("AVD-2", "edited before retry")
	if next("/original") != first || len(requests) != 0 || len(feishu.bodies) != 3 {
		t.Fatal("retry changed the snapshot, followed redirect, or duplicated delivery")
	}
	poll("AVD-2", "after successful retry")
	if len(requests) != 0 {
		t.Fatal("confirmed retry sent again")
	}
}
