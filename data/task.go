package data

import "time"

type Task struct {
	Timestamp time.Time `json:"timestamp"`
}
