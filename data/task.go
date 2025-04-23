package data

type Task struct {
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Event       string `json:"event"`
	Ip          string `json:"ip"`
	Port        int    `json:"port"`
	Flag        string `json:"flag"`
}
