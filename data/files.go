package data

type File struct {
	Filename string `json:"filename"`
	Filepath string `json:"filepath"`
	Size     int    `json:"size"`
	Type     string `json:"type"`
	SHA256   string `json:"sha256"`
}

type Files struct {
	Files []File `json:"files"`
}
