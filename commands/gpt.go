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

const (
	GPT_MODEL  string = "gpt-4o"
	GPT_PROMPT string = `You are a CTF assistant specializing in various categories:

	- **Cryptography**: Decrypting messages, encryption algorithms, cryptographic puzzles.
	- **Steganography**: Detecting hidden information in media files.
	- **Reverse Engineering**: Analyzing binaries, assembly code, understanding compiled programs.
	- **Web Exploitation**: Identifying/exploiting web vulnerabilities (e.g., SQL injection, XSS).
	- **Forensics**: Analyzing disk images, network captures, data recovery.
	- **Binary Exploitation**: Understanding buffer overflows, format string vulnerabilities, low-level attacks.
	- **Miscellaneous**: Logical thinking, problem-solving, technical challenges.

	Provide a concise answer to the following CTF-related question.
	
	Focus on the essential solution and avoid unnecessary details.

	Give your answer in plaintext not markdown.

	CTF Question:`
)

func sendRequest(query map[string]interface{}) {
	body, err := json.Marshal(query)
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.OpenAIKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

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

	if choices, ok := result["choices"].([]interface{}); ok {
		if len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if message, ok := choice["message"].(map[string]interface{}); ok {
					if content, ok := message["content"].(string); ok {
						fmt.Printf("%s\n", content)
					}
				}
			}
		}
	}
}

func readInput(args []string) string {
	content := strings.Join(args[0:], " ")

	if strings.Compare("-", args[0]) == 0 {
		var buffer bytes.Buffer
		_, err := io.Copy(&buffer, os.Stdin)
		if err != nil {
			fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
			os.Exit(1)
		}
		content = buffer.String() + " " + strings.Join(args[1:], " ")
	}

	return content
}

func gptHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "gpt" + theme.ColorGray + " question" + theme.ColorReset + "\n")
	fmt.Printf("  🧠 ask ChatGPT with ret\n")
	fmt.Printf("     " + theme.ColorGray + "use - to read from stdin" + theme.ColorReset + "\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/gpt.go" + theme.ColorReset + "\n")
	os.Exit(0)
}

func Gpt(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			gptHelp()
		}
	} else {
		gptHelp()
		return
	}

	if config.OpenAIKey == "" {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": no OpenAI key found in %s\n", config.UserConfig)
		os.Exit(1)
	}

	content := readInput(args)

	query := map[string]interface{}{
		"model": GPT_MODEL,
		"messages": []map[string]interface{}{
			{
				"role":    "system",
				"content": GPT_PROMPT,
			},
			{
				"role":    "user",
				"content": content,
			},
		},
		"temperature": 0.3,
	}

	sendRequest(query)
}
