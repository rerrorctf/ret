package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"ret/config"
	"ret/theme"
)

func Gist(files map[string]interface{}) string {
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

	url := result["html_url"].(string)

	resp.Body.Close()

	return url
}
