package data

import "time"

type Task struct {
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Ip          string    `json:"ip"`
	Port        int       `json:"port"`
	Url         string    `json:"url"`
}
