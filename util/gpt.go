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

func sendRequest(query map[string]interface{}) string {
	body, err := json.Marshal(query)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(body))
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.OpenAIKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	if choices, ok := result["choices"].([]interface{}); ok {
		if len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if message, ok := choice["message"].(map[string]interface{}); ok {
					if content, ok := message["content"].(string); ok {
						return content
					}
				}
			}
		}
	}

	return ""
}

func Gpt(prompt string, content string) string {
	query := map[string]interface{}{
		"model": config.OpenAIModel,
		"messages": []map[string]interface{}{
			{
				"role":    "system",
				"content": prompt,
			},
			{
				"role":    "user",
				"content": content,
			},
		},
		"temperature": 0.3,
	}

	return sendRequest(query)
}
