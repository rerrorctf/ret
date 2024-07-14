package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"ret/config"
	"ret/theme"
	"strings"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "gist",
		Emoji: "🐙",
		Func:  Gist,
		Help:  GistHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/gist.go",
		Arguments: []Argument{
			{
				Name:     "file",
				Optional: false,
				List:     true,
			},
		}})
}

func GistHelp() {
	fmt.Printf("  🐙 make private gists with ret\n")
	fmt.Printf("     " + theme.ColorGray + "specify the path of one or more files to upload" + theme.ColorReset + "\n")
}

func Gist(args []string) {
	if len(args) == 0 {
		GistHelp()
		return
	}

	if len(config.GistToken) == 0 {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ":  no gist token in ~/.config/ret\n")
	}

	files := map[string]interface{}{}

	for _, file := range args {
		buffer, err := os.ReadFile(file)
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		}

		splits := strings.Split(file, "/")
		filename := splits[len(splits)-1]

		files[filename] = map[string]interface{}{
			"content": string(buffer),
		}
	}

	gist := map[string]interface{}{
		"description": "🐙 made with https://github.com/rerrorctf/ret",
		"public":      false,
		"files":       files,
	}

	body, err := json.Marshal(gist)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	req, err := http.NewRequest("POST", "https://api.github.com/gists", bytes.NewBuffer(body))
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.GistToken))
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	fmt.Printf("%s\n", result["html_url"].(string))

	resp.Body.Close()
}
