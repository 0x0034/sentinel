package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/0x0034/sentinel/internal/model"
)

func TestDurableQueueAndSubscriptionIsolation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := Open(path); err == nil {
		second.Close()
		t.Fatal("second process accepted")
	}
	old := model.Notice{ID: "old", Title: "old", PublishedAt: &now}
	fresh := model.Notice{ID: "new", Title: "new", PublishedAt: &now}
	for _, sub := range []string{"a", "b"} {
		if n, err := s.Ingest(ctx, sub, []model.Notice{old}, map[string][]byte{"old": []byte("old")}, now); err != nil || n != 0 {
			t.Fatalf("baseline: %d %v", n, err)
		}
	}
	for i := 0; i < 2; i++ {
		if _, err := s.Ingest(ctx, "a", []model.Notice{old, fresh}, map[string][]byte{"new": []byte("frozen")}, now); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := s.Pending(ctx, now)
	if err != nil || len(pending) != 1 {
		t.Fatalf("queue: %v %v", pending, err)
	}
	if err := s.Retry(ctx, pending[0], now, "temporary failure"); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Pending(ctx, now.Add(29*time.Second)); len(p) != 0 {
		t.Fatal("retry backoff ignored")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pending, err = s.Pending(ctx, now.Add(30*time.Second))
	if err != nil || len(pending) != 1 || string(pending[0].Payload) != "frozen" {
		t.Fatal("pending task not restored")
	}
	if p, _ := s.Pending(ctx, now.Add(time.Hour), "b"); len(p) != 0 {
		t.Fatal("subscription filter ignored")
	}
	if err := s.Sent(ctx, pending[0].ID, now); err != nil {
		t.Fatal(err)
	}
	fresh.Title = "changed"
	if _, err := s.Ingest(ctx, "a", []model.Notice{fresh}, map[string][]byte{"new": []byte("changed")}, now); err != nil {
		t.Fatal(err)
	}
	if p, _ := s.Pending(ctx, now.Add(time.Hour)); len(p) != 0 {
		t.Fatal("success or edit replayed")
	}
	for i := 0; i < 2; i++ {
		if err := s.EnqueueDigest(ctx, "a", "2026-10-21", [][]byte{[]byte("part1"), []byte("part2")}, now); err != nil {
			t.Fatal(err)
		}
	}
	if p, _ := s.Pending(ctx, now); len(p) != 2 {
		t.Fatalf("digest parts not idempotent: %d", len(p))
	}
}
