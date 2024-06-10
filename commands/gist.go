package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"ret/config"
	"ret/theme"
	"strings"
)

func gistHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "gist" + theme.ColorGray + " file [-]" + theme.ColorReset + "\n")
	fmt.Printf("  🐙 make private gists with ret\n")
	fmt.Printf("     " + theme.ColorGray + "specify the path of the file to upload" + theme.ColorReset + "\n")
	fmt.Printf("     " + theme.ColorGray + "use file - to read from stdin in which case file is used for the name only" + theme.ColorReset + "\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/gist.go" + theme.ColorReset + "\n")
	os.Exit(0)
}

func Gist(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			gistHelp()
		}
	} else {
		gistHelp()
	}

	if len(config.GistToken) == 0 {
		fmt.Printf("💥 " + theme.ColorRed + " error" + theme.ColorReset + ": no gist token in ~/.config/ret\n")
		os.Exit(1)
	}

	file := args[0]

	var content string

	if len(args) > 1 { // assume - but we don't care if not
		var buffer bytes.Buffer
		_, err := io.Copy(&buffer, os.Stdin)
		if err != nil {
			fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
			os.Exit(1)
		}

		content = buffer.String()
	} else {
		buffer, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
			os.Exit(1)
		}

		content = string(buffer)
	}

	splits := strings.Split(file, "/")
	filename := splits[len(splits)-1]

	gist := map[string]interface{}{
		"description": "🐙 made with https://github.com/rerrorctf/ret",
		"public":      false,
		"files": map[string]interface{}{
			filename: map[string]interface{}{
				"content": content,
			},
		},
	}

	body, err := json.Marshal(gist)
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	req, err := http.NewRequest("POST", "https://api.github.com/gists", bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.GistToken))
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		os.Exit(1)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", result["html_url"].(string))

	resp.Body.Close()
}
