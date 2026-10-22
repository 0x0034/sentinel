package feed

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseAndSanitize(t *testing.T) {
	body := `<rss version="2.0"><channel><title>Samples</title><item><guid>a</guid><title>Notice A</title><link>https://example.com/a</link><pubDate>Wed, 21 Oct 2026 17:03:52 +0000</pubDate><description><![CDATA[<p>Hello &amp; world</p><script>secret script</script><style>hidden</style>]]></description></item><item><link>https://example.com/b</link><title>B</title></item><item><guid>a</guid></item><item><title>No identity</title></item></channel></rss>`
	r, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Notices) != 2 || r.Skipped != 1 || r.Undated != 1 {
		t.Fatalf("unexpected result: %+v", r)
	}
	if r.Notices[0].Summary != "Hello & world" || r.Notices[0].PublishedAt == nil {
		t.Fatalf("bad normalization: %+v", r.Notices[0])
	}
	r2, err := Parse(strings.Replace(body, "Notice A", "Changed", 1))
	if err != nil || r2.Notices[0].ID != r.Notices[0].ID {
		t.Fatal("editing title changed identity")
	}
	if len([]rune(Plain(strings.Repeat("中", 1000), 20))) != 21 {
		t.Fatal("unicode truncation failed")
	}
	if _, err := Parse("<html>Not a feed</html>"); err == nil {
		t.Fatal("HTML accepted as feed")
	}
	if _, err := Parse(`<rss version="2.0"><channel><item><title>No identity</title></item></channel></rss>`); err == nil {
		t.Fatal("all-invalid feed must not establish baseline")
	}
}

func TestHTTPFailures(t *testing.T) {
	for _, status := range []int{403, 429, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
			defer srv.Close()
			_, err := NewClient().Fetch(context.Background(), srv.URL)
			if err == nil || !strings.Contains(err.Error(), fmt.Sprint(status)) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, strings.Repeat("x", MaxFeedBytes+1)) }))
	defer srv.Close()
	if _, err := NewClient().Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("oversized response accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewClient().Fetch(ctx, srv.URL+"/private-secret"); err == nil || strings.Contains(err.Error(), "private-secret") {
		t.Fatal("cancellation should fail without URL leakage")
	}
}
