package model

import "time"

type Notice struct {
	ID            string
	Title         string
	Link          string
	Summary       string
	PublishedAt   *time.Time
	FirstSeen     time.Time
	Vulnerability *Vulnerability
}

type Vulnerability struct {
	AVDID          string   `json:"avd_id"`
	CVEID          string   `json:"cve_id"`
	Type           string   `json:"type"`
	Status         string   `json:"status,omitempty"`
	DisclosureDate string   `json:"disclosure_date"`
	CVSS           *float64 `json:"cvss"`
}

type FetchResult struct {
	Notices          []Notice
	Skipped, Undated int
}

type Delivery struct {
	ID           int64
	Subscription string
	Payload      []byte
	Attempts     int
}
