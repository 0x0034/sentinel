package source

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/0x0034/sentinel/internal/model"
	"golang.org/x/net/html"
)

func (c *Client) Detail(ctx context.Context, notice model.Notice) (*model.VulnerabilityDetails, error) {
	u, err := url.Parse(notice.Link)
	if err != nil || notice.Vulnerability == nil || u.Scheme != "https" || u.Host != "avd.aliyun.com" || u.User != nil || u.Path != "/detail" || u.Fragment != "" || len(u.Query()) != 1 || len(u.Query()["id"]) != 1 || u.Query().Get("id") != notice.ID || !avdID.MatchString(notice.ID) {
		return nil, errors.New("invalid Aliyun detail destination")
	}
	body, err := c.Browser.Render(ctx, notice.Link)
	if err != nil {
		return nil, err
	}
	return ParseDetail(body, notice)
}

func ParseDetail(body []byte, notice model.Notice) (*model.VulnerabilityDetails, error) {
	if len(body) > 8<<20 || notice.Vulnerability == nil {
		return nil, errors.New("invalid Aliyun detail input")
	}
	root, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("invalid Aliyun detail HTML")
	}
	titles := byClass(root, "header__title__text")
	crumbs := byClass(root, "breadcrumbs__list")
	if len(titles) != 1 || len(crumbs) != 1 || boundedText(nodeText(titles[0]), 200) != notice.Title {
		return nil, errors.New("Aliyun detail identity missing or mismatched")
	}
	identityOK := false
	for _, token := range strings.Fields(nodeText(crumbs[0])) {
		if token == notice.ID {
			identityOK = true
		}
		for _, cve := range strings.Split(notice.Vulnerability.CVEID, ", ") {
			if cveID.MatchString(cve) && token == cve {
				identityOK = true
			}
		}
	}
	if !identityOK {
		return nil, errors.New("Aliyun detail breadcrumb identity mismatched")
	}
	description, err := detailSection(root, "漏洞描述", true)
	if err != nil {
		return nil, err
	}
	solution, err := detailSection(root, "解决建议", true)
	if err != nil {
		return nil, err
	}
	affected, err := detailSection(root, "受影响软件情况", false)
	if err != nil {
		return nil, err
	}
	d := &model.VulnerabilityDetails{Description: boundedText(detailText(description), 8000), Solution: boundedText(detailText(solution), 8000)}
	if affected != nil {
		d.AffectedSoftware, err = affectedTable(affected)
		if err != nil {
			return nil, err
		}
	} else if match := affectedMarker.FindStringIndex(d.Description); match != nil {
		d.AffectedSoftware = "描述中的影响范围：\n" + boundedText(strings.TrimSpace(d.Description[match[0]:]), 4000)
	}
	for _, header := range byClass(root, "cvss-breakdown__header") {
		heading, scores := byClass(header, "cvss-breakdown__heading"), byClass(header, "cvss-breakdown__score")
		if len(heading) != 1 || nodeText(heading[0]) != "阿里云评分" {
			continue
		}
		if len(scores) != 1 {
			return nil, errors.New("ambiguous Aliyun score")
		}
		if score, err := strconv.ParseFloat(nodeText(scores[0]), 64); err == nil && !math.IsNaN(score) && !math.IsInf(score, 0) && score >= 0 && score <= 10 {
			if d.AliyunScore != nil {
				return nil, errors.New("duplicate Aliyun score")
			}
			d.AliyunScore = &score
		}
	}
	return d, nil
}

var affectedMarker = regexp.MustCompile(`(?:受影响版本|影响版本|受影响软件|影响范围)\s*[：:]`)

func detailSection(root *html.Node, name string, required bool) (*html.Node, error) {
	var section *html.Node
	for _, heading := range descendants(root, "h6") {
		if nodeText(heading) != name {
			continue
		}
		if section != nil {
			return nil, errors.New("duplicate Aliyun detail section")
		}
		n := heading.NextSibling
		for n != nil && n.Type != html.ElementNode {
			n = n.NextSibling
		}
		if n == nil || n.Data != "div" {
			return nil, errors.New("Aliyun detail layout changed")
		}
		section = n
	}
	if required && section == nil {
		return nil, errors.New("Aliyun detail section missing; possible challenge or layout change")
	}
	return section, nil
}

func byClass(root *html.Node, class string) []*html.Node {
	var found []*html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		for _, a := range n.Attr {
			if a.Key == "class" {
				for _, value := range strings.Fields(a.Val) {
					if value == class {
						found = append(found, n)
						break
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)
	return found
}

func detailText(root *html.Node) string {
	var text strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style" || n.Data == "button") {
			return
		}
		block := n.Type == html.ElementNode && (n.Data == "br" || n.Data == "p" || n.Data == "div" || n.Data == "li")
		if block {
			text.WriteByte('\n')
		}
		if n.Type == html.TextNode {
			text.WriteString(n.Data)
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
		if n.Type == html.ElementNode && n.Data == "a" {
			for _, a := range n.Attr {
				if a.Key != "href" {
					continue
				}
				u, err := url.Parse(a.Val)
				if err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil && nodeText(n) != a.Val {
					text.WriteString(" (" + a.Val + ")")
				}
			}
		}
		if block {
			text.WriteByte('\n')
		}
	}
	walk(root)
	var lines []string
	for _, line := range strings.Split(text.String(), "\n") {
		if line = strings.Join(strings.Fields(line), " "); line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}

func affectedTable(section *html.Node) (string, error) {
	tables := descendants(section, "table")
	if len(tables) != 1 {
		return "", errors.New("affected software table missing or ambiguous")
	}
	heads := descendants(tables[0], "thead")
	if len(heads) != 1 || nodeText(heads[0]) != "# 类型 厂商 产品 版本 影响面" {
		return "", errors.New("affected software columns changed")
	}
	bodies := descendants(tables[0], "tbody")
	if len(bodies) != 1 {
		return "", errors.New("affected software body missing")
	}
	var lines []string
	for _, row := range descendants(bodies[0], "tr") {
		cells := descendants(row, "td")
		if len(cells) == 0 {
			continue
		}
		if len(cells) == 1 {
			text := detailText(cells[0])
			if text != "" {
				lines = append(lines, text)
			}
			continue
		}
		labels := []string{"类型", "厂商", "产品", "版本", "影响范围起点", "影响范围终点"}
		if len(cells) == 5 {
			merged := false
			for _, a := range cells[4].Attr {
				if a.Key == "colspan" && a.Val == "2" {
					merged = true
				}
			}
			if !merged {
				return "", errors.New("affected software range columns missing")
			}
			labels = []string{"类型", "厂商", "产品", "版本", "影响范围"}
		} else if len(cells) != 6 {
			return "", errors.New("affected software row changed")
		}
		var fields []string
		for i, cell := range cells {
			if text := nodeText(cell); text != "" {
				fields = append(fields, labels[i]+"："+text)
			}
		}
		lines = append(lines, strings.Join(fields, "；"))
	}
	return boundedText(strings.Join(lines, "\n"), 8000), nil
}
