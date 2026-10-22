package source

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func script(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "browser")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBrowserIsolationAndCleanup(t *testing.T) {
	t.Setenv("FEISHU_WEBHOOK_URL", "test-sensitive-value")
	t.Setenv("OTHER_SECRET", "test-other-secret")
	binary := script(t, `test -z "$FEISHU_WEBHOOK_URL" && test -z "$OTHER_SECRET" || exit 1
for arg in "$@"; do
 case "$arg" in --user-data-dir=*) profile="${arg#*=}";; esac
done
test -d "$profile" || exit 2
printf '%s' "$profile"
`)
	browser := &Chromium{Binary: binary, Timeout: time.Second}
	body, err := browser.Render(context.Background(), "https://example.com/list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "sentinel-chromium-") {
		t.Fatal("no isolated profile")
	}
	if _, err := os.Stat(string(body)); !os.IsNotExist(err) {
		t.Fatal("temporary profile not removed")
	}
}

func TestBrowserBoundsCancellationAndRedaction(t *testing.T) {
	for _, mode := range []string{"timeout", "cancel", "output", "failure"} {
		t.Run(mode, func(t *testing.T) {
			record := filepath.Join(t.TempDir(), "profile-path")
			browserTemp := t.TempDir()
			t.Setenv("TMPDIR", browserTemp)
			body := fmt.Sprintf(`for arg in "$@"; do
case "$arg" in --user-data-dir=*) printf '%%s' "${arg#*=}" > %q;; esac
done
`, record)
			switch mode {
			case "timeout", "cancel":
				body += "sleep 30 &\nwait\n"
			case "output":
				body += "head -c 4096 /dev/zero\n"
			case "failure":
				body += "printf 'private-error' >&2\nexit 1\n"
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timeout := time.Second
			if mode == "timeout" {
				timeout = 100 * time.Millisecond
			}
			if mode == "cancel" {
				timer := time.AfterFunc(100*time.Millisecond, cancel)
				defer timer.Stop()
			}
			browser := &Chromium{Binary: script(t, body), Timeout: timeout, OutputLimit: 128}
			started := time.Now()
			_, err := browser.Render(ctx, "https://example.com/list")
			if err == nil || strings.Contains(err.Error(), "private-error") {
				t.Fatalf("invalid or leaked failure: %v", err)
			}
			expected := "process failed"
			if mode == "timeout" || mode == "cancel" {
				expected = "canceled or timed out"
			}
			if mode == "output" {
				expected = "size limit"
			}
			if !strings.Contains(err.Error(), expected) {
				t.Fatalf("wrong failure mechanism for %s: %v", mode, err)
			}
			if time.Since(started) > 3*time.Second {
				t.Fatal("browser cancellation or output bound did not stop process")
			}
			profile, readErr := os.ReadFile(record)
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if readErr != nil && mode != "timeout" && mode != "cancel" {
				t.Fatal("helper process did not run")
			}
			if readErr == nil {
				if _, err := os.Stat(string(profile)); !os.IsNotExist(err) {
					t.Fatal("failed browser left profile")
				}
			}
			entries, err := os.ReadDir(browserTemp)
			if err != nil || len(entries) != 0 {
				t.Fatal("temporary browser directory leaked")
			}
		})
	}
}
