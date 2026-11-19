package store

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/0x0034/sentinel/internal/config"
	"github.com/0x0034/sentinel/internal/model"
)

// Only the fingerprint of the configured URL belongs in the delivery queue.
func targetKey(rawURL string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(rawURL)))
}

type discoveryEvent struct {
	EventID        string                      `json:"event_id"`
	SubscriptionID string                      `json:"subscription_id"`
	Source         string                      `json:"source"`
	FirstSeen      time.Time                   `json:"first_seen"`
	AVDID          string                      `json:"avd_id"`
	Title          string                      `json:"title"`
	URL            string                      `json:"url"`
	CVEID          string                      `json:"cve_id,omitempty"`
	Type           string                      `json:"type,omitempty"`
	Status         string                      `json:"status,omitempty"`
	DisclosureDate string                      `json:"disclosure_date,omitempty"`
	CVSS           *float64                    `json:"cvss,omitempty"`
	Details        *model.VulnerabilityDetails `json:"details,omitempty"`
}

func newDiscoveryEvent(sub config.Subscription, n model.Notice, now time.Time) discoveryEvent {
	v := n.Vulnerability
	return discoveryEvent{
		EventID: "discovery:" + sub.ID + ":" + v.AVDID, SubscriptionID: sub.ID,
		Source: sub.Type, FirstSeen: now.UTC().Truncate(time.Second),
		AVDID: v.AVDID, Title: n.Title, URL: n.Link, CVEID: v.CVEID,
		Type: v.Type, Status: v.Status, DisclosureDate: v.DisclosureDate, CVSS: v.CVSS, Details: v.Details,
	}
}
