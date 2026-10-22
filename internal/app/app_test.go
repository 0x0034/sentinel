package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0x0034/sentinel/internal/config"
	"github.com/0x0034/sentinel/internal/feed"
	"github.com/0x0034/sentinel/internal/model"
	"github.com/0x0034/sentinel/internal/notify"
	"github.com/0x0034/sentinel/internal/store"
)

type fakeFeed struct {
	result feed.Result
	err    error
}

func (f *fakeFeed) Fetch(context.Context, string) (feed.Result, error) { return f.result, f.err }

type captureSender struct{ bodies []string }

func (s *captureSender) Send(_ context.Context, _ string, b []byte) error {
	s.bodies = append(s.bodies, string(b))
	return nil
}
func testConfig() config.Config {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	return config.Config{Location: loc, DigestHour: 9, PollInterval: time.Hour, Subscriptions: []config.Subscription{{ID: "sample", Name: "Sample", URL: "https://example.com/feed", Webhook: "test-target", Incremental: true, Digest: true}}}
}
func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestHTTPToSQLiteToRobotAndRestart(t *testing.T) {
	baseline, err := os.ReadFile("../../testdata/baseline.xml")
	if err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile("../../testdata/updated.xml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(baseline)
	attempts := 0
	var mu sync.Mutex
	count := func() int { mu.Lock(); defer mu.Unlock(); return attempts }
	setContent := func(body string) { mu.Lock(); defer mu.Unlock(); content = body }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/feed" {
			fmt.Fprint(w, content)
			return
		}
		attempts++
		if attempts == 1 {
			fmt.Fprint(w, `{"code":11232}`)
		} else {
			fmt.Fprint(w, `{"code":0}`)
		}
	}))
	defer srv.Close()
	c := testConfig()
	c.Subscriptions[0].URL = srv.URL + "/feed"
	c.Subscriptions[0].Webhook = srv.URL + "/bot"
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	sender := notify.NewClient()
	sender.MinInterval = 0
	a := New(c, db, feed.NewClient(), sender, quiet())
	ctx := context.Background()
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, c.Location)
	if err := a.Once(ctx, now); err != nil {
		t.Fatal(err)
	}
	if count() != 0 {
		t.Fatal("baseline was sent")
	}
	setContent(string(updated))
	if err := a.Once(ctx, now); err != nil {
		t.Fatal(err)
	}
	if count() != 1 {
		t.Fatal("new notice was not attempted")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a = New(c, db, feed.NewClient(), sender, quiet())
	if err := a.Once(ctx, now.Add(31*time.Second)); err != nil {
		t.Fatal(err)
	}
	if count() != 2 {
		t.Fatal("failed notification did not survive restart")
	}
	setContent(strings.Replace(string(updated), "New test notice", "Edited test notice", 1))
	if err := a.Once(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if count() != 2 {
		t.Fatal("successful or edited notice was resent")
	}
}

func TestDigestDateBoundariesCatchUpAndEmptyDay(t *testing.T) {
	c := testConfig()
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	start := time.Date(2026, 10, 21, 0, 0, 0, 0, c.Location)
	end := start.AddDate(0, 0, 1)
	makeNotice := func(id string, published time.Time) model.Notice {
		return model.Notice{ID: id, Title: id, PublishedAt: &published}
	}
	f := &fakeFeed{result: feed.Result{Notices: []model.Notice{makeNotice("INCLUSIVE_START", start.UTC()), makeNotice("LAST_SECOND", end.Add(-time.Second)), makeNotice("EXCLUDED_END", end), makeNotice("TOO_OLD", start.Add(-time.Second)), {ID: "undated", Title: "UNDATED"}}}}
	sender := &captureSender{}
	a := New(c, db, f, sender, quiet())
	before := end.Add(8*time.Hour + 59*time.Minute)
	if err := a.Once(ctx, before); err != nil {
		t.Fatal(err)
	}
	if len(sender.bodies) != 0 {
		t.Fatal("digest sent before 09:00")
	}
	if err := a.Once(ctx, end.Add(9*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(sender.bodies) != 1 {
		t.Fatalf("got %d cards", len(sender.bodies))
	}
	body := sender.bodies[0]
	for _, title := range []string{"INCLUSIVE_START", "LAST_SECOND"} {
		if !strings.Contains(body, title) {
			t.Fatalf("missing %s", title)
		}
	}
	for _, title := range []string{"EXCLUDED_END", "TOO_OLD", "UNDATED"} {
		if strings.Contains(body, title) {
			t.Fatalf("wrongly included %s", title)
		}
	}
	if err := a.Once(ctx, end.Add(20*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(sender.bodies) != 1 {
		t.Fatal("same day digest duplicated")
	}
	later := end.AddDate(0, 0, 3).Add(10 * time.Hour)
	if err := a.Once(ctx, later); err != nil {
		t.Fatal(err)
	}
	if len(sender.bodies) != 2 || !strings.Contains(sender.bodies[1], "未采集到昨日公告") || !strings.Contains(sender.bodies[1], "2026-10-24") {
		t.Fatal("catch-up should only generate yesterday, including empty day")
	}
}

func TestFailedFetchDoesNotInitializeAndDegradedDigest(t *testing.T) {
	c := testConfig()
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f := &fakeFeed{err: errors.New("RSS returned HTTP 403")}
	sender := &captureSender{}
	a := New(c, db, f, sender, quiet())
	ctx := context.Background()
	now := time.Date(2026, 10, 22, 10, 0, 0, 0, c.Location)
	if err := a.Once(ctx, now); err == nil {
		t.Fatal("failed fetch must be reported")
	}
	if len(sender.bodies) != 1 || !strings.Contains(sender.bodies[0], "抓取失败") {
		t.Fatal("degraded digest must explain missing coverage")
	}
	f.err = nil
	f.result.Notices = []model.Notice{{ID: "old", Title: "old"}}
	if err := a.Once(ctx, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sender.bodies) != 1 {
		t.Fatal("failed request established baseline or duplicated digest")
	}
}

func TestRunStopsOnCancellation(t *testing.T) {
	c := testConfig()
	db, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a := New(c, db, &fakeFeed{}, &captureSender{}, quiet())
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked")
	}
}
