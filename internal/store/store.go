package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/0x0034/sentinel/internal/model"
	_ "modernc.org/sqlite"
)

type Store struct {
	db   *sql.DB
	lock *os.File
}

func Open(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(abs+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("database is already in use by another Sentinel process")
	}
	u := url.URL{Scheme: "file", Path: abs}
	db, err := sql.Open("sqlite", u.String()+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		lock.Close()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, lock: lock}
	if err := s.migrate(); err != nil {
		s.Close()
		return nil, err
	}
	if err := os.Chmod(abs, 0600); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > 2 {
		return errors.New("database schema is newer than this application")
	}
	if _, err := s.db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return err
	}
	if version == 2 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if version == 0 {
		if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS subscriptions (id TEXT PRIMARY KEY, initialized INTEGER NOT NULL DEFAULT 0, last_success INTEGER);
CREATE TABLE IF NOT EXISTS notices (
 subscription TEXT NOT NULL REFERENCES subscriptions(id), id TEXT NOT NULL, title TEXT NOT NULL, link TEXT NOT NULL,
 summary TEXT NOT NULL, published INTEGER, first_seen INTEGER NOT NULL, PRIMARY KEY(subscription,id));
CREATE INDEX IF NOT EXISTS notices_date ON notices(subscription,published);
CREATE TABLE IF NOT EXISTS digests (subscription TEXT NOT NULL REFERENCES subscriptions(id), date TEXT NOT NULL, PRIMARY KEY(subscription,date));
CREATE TABLE IF NOT EXISTS deliveries (
 id INTEGER PRIMARY KEY, subscription TEXT NOT NULL REFERENCES subscriptions(id), task_key TEXT NOT NULL UNIQUE,
 payload BLOB NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL,
 sent_at INTEGER, last_error TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS pending_deliveries ON deliveries(next_attempt,id) WHERE sent_at IS NULL;
`); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`
ALTER TABLE subscriptions ADD COLUMN source_type TEXT NOT NULL DEFAULT 'rss';
ALTER TABLE notices ADD COLUMN baseline INTEGER NOT NULL DEFAULT 1;
ALTER TABLE notices ADD COLUMN vulnerability TEXT NOT NULL DEFAULT '';
CREATE INDEX notices_discovered ON notices(subscription,first_seen) WHERE baseline=0;
PRAGMA user_version=2;`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) EnsureSource(ctx context.Context, sub, kind string) error {
	if kind == "" {
		kind = "rss"
	}
	if _, err := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO subscriptions(id,source_type) VALUES(?,?)", sub, kind); err != nil {
		return err
	}
	var existing string
	if err := s.db.QueryRowContext(ctx, "SELECT source_type FROM subscriptions WHERE id=?", sub).Scan(&existing); err != nil {
		return err
	}
	if existing != kind {
		return errors.New("subscription source type changed; use a new subscription id")
	}
	return nil
}

func (s *Store) Close() error { return errors.Join(s.db.Close(), s.lock.Close()) }

func (s *Store) Ingest(ctx context.Context, sub string, notices []model.Notice, payloads map[string][]byte, now time.Time) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO subscriptions(id) VALUES(?)", sub); err != nil {
		return 0, err
	}
	var initialized bool
	if err = tx.QueryRowContext(ctx, "SELECT initialized FROM subscriptions WHERE id=?", sub).Scan(&initialized); err != nil {
		return 0, err
	}
	count := 0
	for _, n := range notices {
		var exists bool
		if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM notices WHERE subscription=? AND id=?)", sub, n.ID).Scan(&exists); err != nil {
			return 0, err
		}
		var published any
		if n.PublishedAt != nil {
			published = n.PublishedAt.Unix()
		}
		metadata := ""
		if n.Vulnerability != nil {
			encoded, err := json.Marshal(n.Vulnerability)
			if err != nil {
				return 0, err
			}
			metadata = string(encoded)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO notices(subscription,id,title,link,summary,published,first_seen,baseline,vulnerability) VALUES(?,?,?,?,?,?,?,?,?)
ON CONFLICT(subscription,id) DO UPDATE SET title=excluded.title,link=excluded.link,summary=excluded.summary,published=excluded.published,vulnerability=excluded.vulnerability`, sub, n.ID, n.Title, n.Link, n.Summary, published, now.Unix(), !initialized, metadata)
		if err != nil {
			return 0, err
		}
		if !exists && initialized && len(payloads[n.ID]) > 0 {
			if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO deliveries(subscription,task_key,payload,next_attempt) VALUES(?,?,?,?)", sub, "incremental:"+sub+":"+n.ID, payloads[n.ID], now.Unix()); err != nil {
				return 0, err
			}
			count++
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE subscriptions SET initialized=1,last_success=? WHERE id=?", now.Unix(), sub); err != nil {
		return 0, err
	}
	return count, tx.Commit()
}

func (s *Store) DigestExists(ctx context.Context, sub, date string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM digests WHERE subscription=? AND date=?)", sub, date).Scan(&exists)
	return exists, err
}

func (s *Store) NoticesBetween(ctx context.Context, sub string, start, end time.Time) ([]model.Notice, error) {
	return s.between(ctx, sub, start, end, false)
}
func (s *Store) DiscoveredBetween(ctx context.Context, sub string, start, end time.Time) ([]model.Notice, error) {
	return s.between(ctx, sub, start, end, true)
}
func (s *Store) between(ctx context.Context, sub string, start, end time.Time, discovered bool) ([]model.Notice, error) {
	predicate, order := "published>=? AND published<?", "published,id"
	if discovered {
		predicate, order = "first_seen>=? AND first_seen<? AND baseline=0", "first_seen,id"
	}
	rows, err := s.db.QueryContext(ctx, "SELECT id,title,link,summary,published,first_seen,vulnerability FROM notices WHERE subscription=? AND "+predicate+" ORDER BY "+order, sub, start.Unix(), end.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.Notice
	for rows.Next() {
		var n model.Notice
		var published sql.NullInt64
		var firstSeen int64
		var metadata string
		if err := rows.Scan(&n.ID, &n.Title, &n.Link, &n.Summary, &published, &firstSeen, &metadata); err != nil {
			return nil, err
		}
		if published.Valid {
			date := time.Unix(published.Int64, 0)
			n.PublishedAt = &date
		}
		n.FirstSeen = time.Unix(firstSeen, 0)
		if metadata != "" {
			if err := json.Unmarshal([]byte(metadata), &n.Vulnerability); err != nil {
				return nil, errors.New("invalid stored vulnerability metadata")
			}
		}
		result = append(result, n)
	}
	return result, rows.Err()
}

func (s *Store) EnqueueDigest(ctx context.Context, sub, date string, payloads [][]byte, now time.Time) error {
	if len(payloads) == 0 {
		return errors.New("digest must contain at least one card")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO subscriptions(id) VALUES(?)", sub); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO digests(subscription,date) VALUES(?,?)", sub, date)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return nil
	}
	for i, payload := range payloads {
		if _, err = tx.ExecContext(ctx, "INSERT INTO deliveries(subscription,task_key,payload,next_attempt) VALUES(?,?,?,?)", sub, fmt.Sprintf("digest:%s:%s:%d", sub, date, i), payload, now.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Pending(ctx context.Context, now time.Time, subscriptions ...string) ([]model.Delivery, error) {
	query := "SELECT id,subscription,payload,attempts FROM deliveries WHERE sent_at IS NULL AND next_attempt<=?"
	args := []any{now.Unix()}
	if len(subscriptions) > 0 {
		query += " AND subscription IN (" + strings.TrimSuffix(strings.Repeat("?,", len(subscriptions)), ",") + ")"
		for _, sub := range subscriptions {
			args = append(args, sub)
		}
	}
	query += " ORDER BY id LIMIT 100"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.Delivery
	for rows.Next() {
		var d model.Delivery
		if err := rows.Scan(&d.ID, &d.Subscription, &d.Payload, &d.Attempts); err != nil {
			return nil, err
		}
		result = append(result, d)
	}
	return result, rows.Err()
}

func (s *Store) Sent(ctx context.Context, id int64, now time.Time) error {
	_, err := s.db.ExecContext(ctx, "UPDATE deliveries SET sent_at=?,last_error='' WHERE id=?", now.Unix(), id)
	return err
}

func (s *Store) Retry(ctx context.Context, d model.Delivery, now time.Time, reason string) error {
	delay := 30 * time.Second
	for i := 0; i < d.Attempts && delay < 30*time.Minute; i++ {
		delay *= 2
	}
	if delay > 30*time.Minute {
		delay = 30 * time.Minute
	}
	_, err := s.db.ExecContext(ctx, "UPDATE deliveries SET attempts=attempts+1,next_attempt=?,last_error=? WHERE id=?", now.Add(delay).Unix(), reason, d.ID)
	return err
}
