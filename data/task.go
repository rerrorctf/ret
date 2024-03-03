package data

import "time"

type Task struct {
	FlagFormat string    `json:"flagformat"`
	Timestamp  time.Time `json:"timestamp"`
}
