package model

import "time"

type Notice struct {
	ID          string
	Title       string
	Link        string
	Summary     string
	PublishedAt *time.Time
}

type Delivery struct {
	ID           int64
	Subscription string
	Payload      []byte
	Attempts     int
}
