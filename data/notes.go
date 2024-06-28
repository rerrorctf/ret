package data

import "time"

type Note struct {
	Note      string    `json:"note"`
	Timestamp time.Time `json:"time"`
}

type Notes struct {
	Notes []Note `json:"notes"`
}
