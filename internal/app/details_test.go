package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0x0034/sentinel/internal/config"
	"github.com/0x0034/sentinel/internal/model"
	"github.com/0x0034/sentinel/internal/store"
)

type detailFeed struct {
	items []model.Notice
	calls []string
	fail  bool
}

func (f *detailFeed) Fetch(context.Context, config.Subscription) (model.FetchResult, error) {
	items := make([]model.Notice, len(f.items))
	for i, n := range f.items {
		items[i] = n
		v := *n.Vulnerability
		items[i].Vulnerability = &v
	}
	return model.FetchResult{Notices: items}, nil
}
func (f *detailFeed) Detail(ctx context.Context, n model.Notice) (*model.VulnerabilityDetails, error) {
	f.calls = append(f.calls, n.ID)
	if f.fail {
		return nil, errors.New("detail temporarily unavailable")
	}
	score := 8.2
	return &model.VulnerabilityDetails{Description: "真实来源描述", Solution: "升级组件至 2.0", AffectedSoftware: "组件 < 2.0", AliyunScore: &score}, nil
}
func detailNotice(id string) model.Notice {
	return model.Notice{ID: id, Title: id, Vulnerability: &model.Vulnerability{AVDID: id, DisclosureDate: "2020-01-01"}}
}

func TestDetailsCacheRetryDigestAndRestart(t *testing.T) {
	c := testConfig()
	c.Subscriptions[0].Type = config.AliyunHighRisk
	path := filepath.Join(t.TempDir(), "details.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { db.Close() }()
	f := &detailFeed{items: []model.Notice{detailNotice("baseline")}}
	sender := &captureSender{}
	a := New(c, db, f, sender, quiet())
	ctx := context.Background()
	baseline := time.Date(2026, 10, 20, 8, 0, 0, 0, c.Location)
	a.Now = func() time.Time { return baseline }
	if err := a.Poll(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 0 {
		t.Fatal("baseline fetched historical details")
	}
	discovered := baseline.AddDate(0, 0, 1)
	a.Now = func() time.Time { return discovered }
	f.items = append(f.items, detailNotice("new"))
	f.fail = true
	if err := a.Once(ctx, discovered); err != nil {
		t.Fatal(err)
	}
	if len(sender.bodies) != 1 || !strings.Contains(sender.bodies[0], "详情暂未获取") || len(f.calls) != 1 {
		t.Fatal("detail failure blocked new notification")
	}
	f.fail = false
	if err := a.Once(ctx, discovered.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(sender.bodies) != 1 || len(f.calls) != 2 {
		t.Fatal("detail retry resent incremental or did not retry")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	a = New(c, db, f, sender, quiet())
	a.Now = func() time.Time { return discovered.Add(2 * time.Minute) }
	if err := a.Poll(ctx, discovered); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 2 {
		t.Fatal("restart lost persisted detail cache")
	}
	due := time.Date(2026, 10, 22, 9, 0, 0, 0, c.Location)
	if err := a.Digests(ctx, due); err != nil {
		t.Fatal(err)
	}
	if err := a.Drain(ctx, due); err != nil {
		t.Fatal(err)
	}
	if len(sender.bodies) != 2 {
		t.Fatal("unexpected deliveries")
	}
	for _, want := range []string{"昨日新发现", "真实来源描述", "升级组件至 2.0", "阿里云评分：8.2", "受影响软件情况"} {
		if !strings.Contains(sender.bodies[1], want) {
			t.Fatalf("digest missing %s", want)
		}
	}
	if strings.Contains(sender.bodies[1], "baseline") {
		t.Fatal("baseline leaked into digest")
	}
}

func TestDetailsLookupLimitRetriesUnattemptedBeforeFailures(t *testing.T) {
	c := testConfig()
	c.Subscriptions[0].Type = config.AliyunHighRisk
	db, err := store.Open(filepath.Join(t.TempDir(), "bounded.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	f := &detailFeed{fail: true}
	a := New(c, db, f, &captureSender{}, quiet())
	ctx := context.Background()
	now := time.Now()
	if err := a.Poll(ctx, now); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		f.items = append(f.items, detailNotice(fmt.Sprintf("item-%02d", i)))
	}
	if err := a.Poll(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 20 {
		t.Fatalf("detail requests not bounded: %d", len(f.calls))
	}
	if err := a.Poll(ctx, now); err != nil {
		t.Fatal(err)
	}
	if f.calls[20] != "item-20" || f.calls[24] != "item-24" {
		t.Fatal("failed requests starved unattempted records")
	}
}
