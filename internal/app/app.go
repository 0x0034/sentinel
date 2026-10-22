package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/0x0034/sentinel/internal/config"
	"github.com/0x0034/sentinel/internal/feed"
	"github.com/0x0034/sentinel/internal/model"
	"github.com/0x0034/sentinel/internal/notify"
	"github.com/0x0034/sentinel/internal/store"
)

type Fetcher interface {
	Fetch(context.Context, string) (feed.Result, error)
}
type Sender interface {
	Send(context.Context, string, []byte) error
}

type fetchErrors struct{ err error }

func (e *fetchErrors) Error() string { return e.err.Error() }

func transientFetch(err error) bool {
	var failures *fetchErrors
	return errors.As(err, &failures)
}

type App struct {
	Config  config.Config
	Store   *store.Store
	Fetcher Fetcher
	Sender  Sender
	Log     *slog.Logger
	failed  map[string]bool
}

func New(c config.Config, s *store.Store, f Fetcher, n Sender, log *slog.Logger) *App {
	return &App{Config: c, Store: s, Fetcher: f, Sender: n, Log: log, failed: map[string]bool{}}
}

func (a *App) Poll(ctx context.Context, now time.Time) error {
	var failures []error
	for _, sub := range a.Config.Subscriptions {
		result, err := a.Fetcher.Fetch(ctx, sub.URL)
		if err != nil {
			a.failed[sub.ID] = true
			a.Log.Warn("feed fetch failed", "subscription", sub.ID, "error", err)
			failures = append(failures, fmt.Errorf("subscription %s fetch failed", sub.ID))
			continue
		}
		payloads := map[string][]byte{}
		if sub.Incremental {
			for _, notice := range result.Notices {
				payload, err := notify.Incremental(sub.Name, notice, a.Config.Location)
				if err != nil {
					return err
				}
				payloads[notice.ID] = payload
			}
		}
		count, err := a.Store.Ingest(ctx, sub.ID, result.Notices, payloads, now)
		if err != nil {
			return err
		}
		a.failed[sub.ID] = false
		a.Log.Info("feed saved", "subscription", sub.ID, "notices", len(result.Notices), "queued", count, "skipped", result.Skipped, "undated", result.Undated)
	}
	if err := errors.Join(failures...); err != nil {
		return &fetchErrors{err: err}
	}
	return nil
}

func (a *App) Digests(ctx context.Context, now time.Time) error {
	local := now.In(a.Config.Location)
	today := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, a.Config.Location)
	due := time.Date(local.Year(), local.Month(), local.Day(), a.Config.DigestHour, a.Config.DigestMinute, 0, 0, a.Config.Location)
	if local.Before(due) {
		return nil
	}
	start := today.AddDate(0, 0, -1)
	date := start.Format("2006-01-02")
	for _, sub := range a.Config.Subscriptions {
		if !sub.Digest {
			continue
		}
		exists, err := a.Store.DigestExists(ctx, sub.ID, date)
		if err != nil {
			return err
		}
		if exists {
			continue
		}
		notices, err := a.Store.NoticesBetween(ctx, sub.ID, start, today)
		if err != nil {
			return err
		}
		payloads, err := notify.Digest(sub.Name, date, notices, a.Config.Location, a.failed[sub.ID])
		if err != nil {
			return err
		}
		if err := a.Store.EnqueueDigest(ctx, sub.ID, date, payloads, now); err != nil {
			return err
		}
		a.Log.Info("digest queued", "subscription", sub.ID, "date", date, "notices", len(notices), "cards", len(payloads))
	}
	return nil
}

func (a *App) Drain(ctx context.Context, now time.Time) error {
	started := time.Now()
	subs := map[string]config.Subscription{}
	ids := []string{}
	for _, sub := range a.Config.Subscriptions {
		subs[sub.ID] = sub
		ids = append(ids, sub.ID)
	}
	pending, err := a.Store.Pending(ctx, now, ids...)
	if err != nil {
		return err
	}
	for _, d := range pending {
		if err := ctx.Err(); err != nil {
			return err
		}
		sub := subs[d.Subscription]
		if err := a.Sender.Send(ctx, sub.Webhook, d.Payload); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if retryErr := a.Store.Retry(ctx, d, now.Add(time.Since(started)), err.Error()); retryErr != nil {
				return retryErr
			}
			a.Log.Warn("notification scheduled for retry", "subscription", sub.ID, "delivery", d.ID, "error", err)
			continue
		}
		if err := a.Store.Sent(ctx, d.ID, now.Add(time.Since(started))); err != nil {
			return err
		}
		a.Log.Info("notification sent", "subscription", sub.ID, "delivery", d.ID)
	}
	return nil
}

func (a *App) Once(ctx context.Context, now time.Time) error {
	pollErr := a.Poll(ctx, now)
	if pollErr != nil && !transientFetch(pollErr) {
		return pollErr
	}
	if err := a.Digests(ctx, now); err != nil {
		return err
	}
	if err := a.Drain(ctx, now); err != nil {
		return err
	}
	return pollErr
}

func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	workerDone := make(chan error, 1)
	workerStopped := make(chan struct{})
	go func() {
		defer close(workerStopped)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if err := a.Drain(ctx, now); err != nil {
					if ctx.Err() == nil {
						workerDone <- err
					}
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-workerStopped }()
	if err := a.Poll(ctx, time.Now()); err != nil {
		if ctx.Err() != nil {
			return nil
		}
		if !transientFetch(err) {
			return err
		}
		a.Log.Warn("poll completed with errors")
	}
	if err := a.Digests(ctx, time.Now()); err != nil {
		return err
	}
	poll := time.NewTicker(a.Config.PollInterval)
	defer poll.Stop()
	schedule := time.NewTicker(time.Second)
	defer schedule.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-workerDone:
			return err
		case <-poll.C:
			if err := a.Poll(ctx, time.Now()); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				if !transientFetch(err) {
					return err
				}
				a.Log.Warn("poll completed with errors")
			}
			if err := a.Digests(ctx, time.Now()); err != nil {
				return err
			}
		case <-schedule.C:
			if err := a.Digests(ctx, time.Now()); err != nil {
				return err
			}
		}
	}
}

func TestNotices(now time.Time, loc *time.Location) []model.Notice {
	local := now.In(loc)
	yesterday := time.Date(local.Year(), local.Month(), local.Day()-1, 12, 0, 0, 0, loc)
	return []model.Notice{{ID: "sentinel-test", Title: "【测试样例】Sentinel 公告通知验证", Summary: "这是一条测试样例，用于验证红色消息卡片、发布时间、摘要与原文链接；不是阿里云实际公告。", Link: "https://github.com/0x0034/sentinel", PublishedAt: &yesterday}}
}
