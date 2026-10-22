package source

import (
	"bytes"
	"errors"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/0x0034/sentinel/internal/model"
	"golang.org/x/net/html"
)

type AliyunPage struct {
	model.FetchResult
	TotalPages int
}

var pagination = regexp.MustCompile(`第\s*(\d+)\s*页\s*/\s*(\d+)\s*页\s*[•·]?\s*总计\s*(\d+)\s*条记录`)
var avdID = regexp.MustCompile(`^AVD-[A-Za-z0-9-]{1,100}$`)
var cveID = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

func ParseCVEPage(body []byte, expectedPage int) (AliyunPage, error) {
	return parseAliyunPage(body, expectedPage, false)
}

func ParseHighRiskPage(body []byte, expectedPage int) (AliyunPage, error) {
	return parseAliyunPage(body, expectedPage, true)
}

func parseAliyunPage(body []byte, expectedPage int, highRisk bool) (AliyunPage, error) {
	var page AliyunPage
	if len(body) > 8<<20 {
		return page, errors.New("Aliyun page exceeds size limit")
	}
	root, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return page, errors.New("invalid Aliyun HTML")
	}
	markers := pagination.FindAllStringSubmatch(nodeText(root), -1)
	if len(markers) == 0 {
		return page, errors.New("Aliyun pagination missing; possible challenge or layout change")
	}
	current, _ := strconv.Atoi(markers[0][1])
	total, _ := strconv.Atoi(markers[0][2])
	count, _ := strconv.ParseInt(markers[0][3], 10, 64)
	if current != expectedPage || current < 1 || total < current || count < 0 || (count == 0 && (current != 1 || total != 1)) {
		return page, errors.New("invalid or mismatched Aliyun pagination")
	}
	for _, m := range markers[1:] {
		if strings.Join(m[1:], ":") != strings.Join(markers[0][1:], ":") {
			return page, errors.New("inconsistent Aliyun pagination")
		}
	}
	page.TotalPages = total
	identity, extra := "CVE编号", "CVSS评分"
	if highRisk {
		identity, extra = "AVD编号", "漏洞状态"
	}
	headers := []string{identity, "漏洞名称", "漏洞类型", "披露时间", extra}
	var table *html.Node
	var columns map[string]int
	for _, candidate := range descendants(root, "table") {
		th := descendants(candidate, "th")
		if len(th) != len(headers) {
			continue
		}
		found := map[string]int{}
		for i, n := range th {
			found[nodeText(n)] = i
		}
		valid := true
		for _, name := range headers {
			if _, ok := found[name]; !ok {
				valid = false
			}
		}
		if valid {
			if table != nil {
				return page, errors.New("ambiguous Aliyun table")
			}
			table, columns = candidate, found
		}
	}
	if table == nil {
		return page, errors.New("Aliyun table missing; possible challenge or layout change")
	}
	bodies := descendants(table, "tbody")
	if len(bodies) != 1 {
		return page, errors.New("invalid Aliyun table body")
	}
	seen := map[string]bool{}
	base, _ := url.Parse("https://avd.aliyun.com")
	for _, row := range descendants(bodies[0], "tr") {
		cells := descendants(row, "td")
		if count == 0 && len(cells) == 1 && strings.Contains(nodeText(cells[0]), "暂无") {
			continue
		}
		if len(cells) != 5 {
			return page, errors.New("incomplete Aliyun row")
		}
		links := descendants(cells[columns[identity]], "a")
		if len(links) != 1 {
			return page, errors.New("Aliyun identity link missing")
		}
		raw := ""
		for _, a := range links[0].Attr {
			if a.Key == "href" {
				raw = a.Val
			}
		}
		u, err := url.Parse(raw)
		if err != nil || raw == "" {
			return page, errors.New("invalid Aliyun detail link")
		}
		u = base.ResolveReference(u)
		id := u.Query().Get("id")
		if u.Scheme != "https" || u.Host != "avd.aliyun.com" || u.User != nil || u.Path != "/detail" || !avdID.MatchString(id) || len(u.Query()["id"]) != 1 {
			return page, errors.New("invalid AVD identity or detail destination")
		}
		if seen[id] {
			return page, errors.New("duplicate AVD identity")
		}
		seen[id] = true
		label := nodeText(links[0])
		rawTitle := nodeText(cells[columns["漏洞名称"]])
		cve := label
		if highRisk {
			if label != id {
				return page, errors.New("AVD label and detail identity disagree")
			}
			cve = titleCVE(rawTitle)
		} else if !cveID.MatchString(cve) {
			cve = ""
		}
		title := boundedText(rawTitle, 200)
		if title == "" {
			return page, errors.New("Aliyun title missing")
		}
		v := &model.Vulnerability{AVDID: id, CVEID: cve, Type: boundedText(nodeText(cells[columns["漏洞类型"]]), 120)}
		disclosed := nodeText(cells[columns["披露时间"]])
		if date, err := time.Parse("2006-01-02", disclosed); err == nil && date.Format("2006-01-02") == disclosed {
			v.DisclosureDate = disclosed
		} else {
			page.Undated++
		}
		if highRisk {
			v.Status = boundedText(nodeText(cells[columns[extra]]), 120)
		} else if score, err := strconv.ParseFloat(nodeText(cells[columns[extra]]), 64); err == nil && !math.IsNaN(score) && !math.IsInf(score, 0) && score >= 0 && score <= 10 {
			v.CVSS = &score
		}
		page.Notices = append(page.Notices, model.Notice{ID: id, Title: title, Link: "https://avd.aliyun.com/detail?id=" + url.QueryEscape(id), Vulnerability: v})
	}
	if (count > 0 && len(page.Notices) == 0) || (count == 0 && len(page.Notices) > 0) || int64(len(page.Notices)) > count {
		return page, errors.New("Aliyun table and record count disagree")
	}
	return page, nil
}

func descendants(n *html.Node, tag string) []*html.Node {
	var found []*html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == tag {
			found = append(found, n)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return found
}
func nodeText(n *html.Node) string {
	var text strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style") {
			return
		}
		if n.Type == html.TextNode {
			text.WriteString(n.Data)
			text.WriteByte(' ')
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return strings.Join(strings.Fields(text.String()), " ")
}

func boundedText(text string, limit int) string {
	runes := []rune(text)
	if len(runes) > limit {
		return string(runes[:limit]) + "…"
	}
	return text
}

var titleCVEPattern = regexp.MustCompile(`\bCVE-\d{4}-\d{4,}\b`)

func titleCVE(title string) string {
	var ids []string
	seen := map[string]bool{}
	for _, id := range titleCVEPattern.FindAllString(title, -1) {
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	return strings.Join(ids, ", ")
}
