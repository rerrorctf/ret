package data

import "time"

type File struct {
	Filename  string    `json:"filename"`
	Filepath  string    `json:"filepath"`
	Size      int       `json:"size"`
	Type      string    `json:"type"`
	Comment   string    `json:"comment"`
	MD5       string    `json:"md5"`
	SHA1      string    `json:"sha1"`
	SHA256    string    `json:"sha256"`
	Timestamp time.Time `json:"timestamp"`
}

type Files struct {
	Files []File `json:"files"`
}
