package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/0x0034/sentinel/internal/model"
)

func TestVersionOneMigrationPreservesRSSAndPendingPayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec(`
CREATE TABLE subscriptions (id TEXT PRIMARY KEY, initialized INTEGER NOT NULL DEFAULT 0, last_success INTEGER);
CREATE TABLE notices (subscription TEXT NOT NULL REFERENCES subscriptions(id),id TEXT NOT NULL,title TEXT NOT NULL,link TEXT NOT NULL,summary TEXT NOT NULL,published INTEGER,first_seen INTEGER NOT NULL,PRIMARY KEY(subscription,id));
CREATE INDEX notices_date ON notices(subscription,published);
CREATE TABLE digests (subscription TEXT NOT NULL REFERENCES subscriptions(id),date TEXT NOT NULL,PRIMARY KEY(subscription,date));
CREATE TABLE deliveries (id INTEGER PRIMARY KEY,subscription TEXT NOT NULL REFERENCES subscriptions(id),task_key TEXT NOT NULL UNIQUE,payload BLOB NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL,sent_at INTEGER,last_error TEXT NOT NULL DEFAULT '');
CREATE INDEX pending_deliveries ON deliveries(next_attempt,id) WHERE sent_at IS NULL;
INSERT INTO subscriptions VALUES('rss',1,1000);
INSERT INTO notices VALUES('rss','old','Old RSS','https://example.com','','1000',500);
INSERT INTO deliveries(subscription,task_key,payload,next_attempt) VALUES('rss','old-task',X'66726f7a656e',1000);
INSERT INTO digests VALUES('rss','2026-10-20');
PRAGMA user_version=1;`)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	now := time.Unix(2000, 0)
	items, err := db.NoticesBetween(ctx, "rss", time.Unix(0, 0), now)
	if err != nil || len(items) != 1 || items[0].Title != "Old RSS" || items[0].FirstSeen.Unix() != 500 {
		t.Fatalf("RSS record changed: %+v %v", items, err)
	}
	pending, err := db.Pending(ctx, now)
	if err != nil || len(pending) != 1 || string(pending[0].Payload) != "frozen" {
		t.Fatal("pending payload lost")
	}
	if exists, err := db.DigestExists(ctx, "rss", "2026-10-20"); err != nil || !exists {
		t.Fatal("digest marker lost")
	}
	if err := db.EnsureSource(ctx, "rss", "aliyun_cve"); err == nil {
		t.Fatal("source type change reused old state")
	}
	if queued, err := db.Ingest(ctx, "rss", items, map[string][]byte{"old": []byte("should-not-send")}, now); err != nil || queued != 0 {
		t.Fatal("existing baseline was reset")
	}
	var version int
	if err := db.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 2 {
		t.Fatal("schema migration not completed")
	}
}

func TestDiscoveryWindowExcludesBaselineAndSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cve.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	start := time.Date(2026, 10, 21, 0, 0, 0, 0, time.FixedZone("CST", 8*3600))
	end := start.AddDate(0, 0, 1)
	makeNotice := func(id string) model.Notice {
		return model.Notice{ID: id, Title: id, Vulnerability: &model.Vulnerability{AVDID: id, CVEID: "CVE-2020-10001", DisclosureDate: "2020-01-01"}}
	}
	if err := db.EnsureSource(ctx, "cve", "aliyun_cve"); err != nil {
		t.Fatal(err)
	}
	for _, sample := range []struct {
		n  model.Notice
		at time.Time
	}{
		{makeNotice("baseline"), start},
		{makeNotice("inclusive"), start},
		{makeNotice("last-second"), end.Add(-time.Second)},
		{makeNotice("excluded-end"), end},
	} {
		if _, err := db.Ingest(ctx, "cve", []model.Notice{sample.n}, nil, sample.at); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	edited := makeNotice("inclusive")
	edited.Title = "edited"
	score := 9.8
	edited.Vulnerability.CVSS = &score
	edited.Vulnerability.Status = "CVE 武器化"
	if _, err := db.Ingest(ctx, "cve", []model.Notice{edited}, nil, end.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	items, err := db.DiscoveredBetween(ctx, "cve", start, end)
	if err != nil || len(items) != 2 {
		t.Fatalf("wrong discovered records: %+v %v", items, err)
	}
	if items[0].ID != "inclusive" || items[0].Title != "edited" || !items[0].FirstSeen.Equal(start) || items[0].Vulnerability.CVSS == nil || *items[0].Vulnerability.CVSS != 9.8 || items[0].Vulnerability.Status != "CVE 武器化" {
		t.Fatal("first seen or metadata not preserved")
	}
	if items[1].ID != "last-second" {
		t.Fatal("wrong date boundary")
	}
}
