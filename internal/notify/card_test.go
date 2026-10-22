package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/0x0034/sentinel/internal/model"
)

func TestV2CardSeparatesMetadataAndDetailSections(t *testing.T) {
	score := 8.2
	n := model.Notice{Title: "Node.js 漏洞", Link: "https://avd.aliyun.com/detail?id=AVD-2026-111497", Vulnerability: &model.Vulnerability{
		AVDID: "AVD-2026-111497", CVEID: "CVE-2026-111497", DisclosureDate: "2026-10-20", Type: "远程代码执行", Status: "PoC",
		Details: &model.VulnerabilityDetails{Description: "保留\n原始段落", Solution: "升级至安全版本", AffectedSoftware: "Node.js：>= 20.0, < 20.20", AliyunScore: &score},
	}}
	body, err := Incremental("高风险", n, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Card struct {
			Schema string                                     `json:"schema"`
			Config struct{ Summary struct{ Content string } } `json:"config"`
			Header struct{ Template string }                  `json:"header"`
			Body   struct{ Elements []map[string]any }        `json:"body"`
		} `json:"card"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Card.Schema != "2.0" || payload.Card.Header.Template != "red" || payload.Card.Config.Summary.Content == "" {
		t.Fatal("missing v2 declaration, red header or chat preview")
	}
	var headings []string
	var sections []string
	var columns, buttons int
	for _, e := range payload.Card.Body.Elements {
		switch e["tag"] {
		case "markdown":
			headings = append(headings, e["content"].(string))
		case "div":
			text := e["text"].(map[string]any)
			sections = append(sections, text["content"].(string))
			if text["content"] == n.Title && text["text_size"] != "heading" {
				t.Fatal("notice title lacks visual hierarchy")
			}
		case "column_set":
			columns++
			if e["flex_mode"] != "stretch" || len(e["columns"].([]any)) != 2 {
				t.Fatal("metadata must stack on narrow screens")
			}
		case "button":
			buttons++
			behaviors := e["behaviors"].([]any)
			b := behaviors[0].(map[string]any)
			if len(behaviors) != 1 || b["type"] != "open_url" || b["default_url"] != n.Link {
				t.Fatal("original URL must use v2 open_url behavior")
			}
		}
	}
	if columns < 2 || buttons != 1 || strings.Join(headings, "|") != "**漏洞描述**|**解决建议**|**受影响软件情况**" {
		t.Fatalf("missing structured metadata or detail headings: %v", headings)
	}
	for _, value := range []string{n.Title, n.Vulnerability.Details.Description, n.Vulnerability.Details.Solution, n.Vulnerability.Details.AffectedSoftware} {
		found := false
		for _, text := range sections {
			found = found || text == value
		}
		if !found {
			t.Fatalf("detail is not in its own text component: %q", value)
		}
	}
	for _, value := range []string{"阿里云评分：8.2 / 10", "CVSS：未知", "披露日期：2026-10-20", "漏洞状态：PoC"} {
		if !strings.Contains(string(body), value) {
			t.Fatalf("missing %s", value)
		}
	}
	if strings.Contains(string(body), "首次发现：") {
		t.Fatal("invented discovery time")
	}
}

func TestCardSourceTextCannotCreateMarkupOrMentions(t *testing.T) {
	value := "<at id=all></at> **bold** [link](https://example.com) a_b >= 1 && < 2\nsecond line"
	n := model.Notice{Title: value, Summary: value, Link: "javascript:alert(1)", Vulnerability: &model.Vulnerability{
		AVDID: value, CVEID: value, Type: value, Status: value, DisclosureDate: value,
		Details: &model.VulnerabilityDetails{Description: value, Solution: value, AffectedSoftware: value},
	}}
	body, err := Incremental(value, n, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	var root any
	if err := json.Unmarshal(body, &root); err != nil {
		t.Fatal(err)
	}
	plainTexts := 0
	walkCardJSON(root, func(m map[string]any) {
		if m["tag"] == "button" {
			t.Error("unsafe original URL became clickable")
		}
		if m["tag"] == "markdown" && strings.Contains(m["content"].(string), "<at") {
			t.Error("source became executable markdown")
		}
		if content, ok := m["content"].(string); ok && strings.Contains(content, value) && m["tag"] == "plain_text" {
			plainTexts += strings.Count(content, value)
		}
	})
	if plainTexts < 9 {
		t.Fatalf("source text was escaped, dropped or not plain text: %d fields", plainTexts)
	}
}

func TestDigestSplitsBeforeV2ElementLimit(t *testing.T) {
	for _, vulnerabilities := range []bool{false, true} {
		t.Run(fmt.Sprintf("vulnerabilities=%v", vulnerabilities), func(t *testing.T) {
			var notices []model.Notice
			for i := 0; i < 120; i++ {
				n := model.Notice{Title: fmt.Sprintf("ITEM-%03d", i)}
				if vulnerabilities {
					n.Vulnerability = &model.Vulnerability{AVDID: fmt.Sprintf("AVD-2026-%d", 10000+i)}
				}
				notices = append(notices, n)
			}
			cards, err := Digest("测试", "2026-10-22", notices, time.UTC, false)
			if err != nil {
				t.Fatal(err)
			}
			if len(cards) < 2 {
				t.Fatal("digest was not split")
			}
			counts := map[string]int{}
			for _, body := range cards {
				var root any
				if err := json.Unmarshal(body, &root); err != nil {
					t.Fatal(err)
				}
				elements := 0
				walkCardJSON(root, func(m map[string]any) {
					if _, ok := m["tag"]; ok {
						elements++
					}
					if m["tag"] == "plain_text" {
						if s, ok := m["content"].(string); ok && strings.HasPrefix(s, "ITEM-") {
							counts[s]++
						}
					}
				})
				if elements > 200 || len(body) > MaxPayloadBytes {
					t.Fatalf("card exceeds API limit: %d elements, %d bytes", elements, len(body))
				}
			}
			for _, n := range notices {
				if counts[n.Title] != 1 {
					t.Fatalf("lost or duplicate notice %s: %d", n.Title, counts[n.Title])
				}
			}
		})
	}
}

func walkCardJSON(value any, visit func(map[string]any)) {
	switch value := value.(type) {
	case map[string]any:
		visit(value)
		for _, child := range value {
			walkCardJSON(child, visit)
		}
	case []any:
		for _, child := range value {
			walkCardJSON(child, visit)
		}
	}
}
