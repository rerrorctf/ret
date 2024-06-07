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

func gptHelp() {
	fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"gpt"+theme.ColorGray+" question"+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, "  🧠 ask ChatGPT with ret\n")
	fmt.Fprintf(os.Stderr, "     "+theme.ColorGray+"use - to read from stdin"+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, "  🔗 "+theme.ColorGray+"https://github.com/rerrorctf/ret/blob/main/commands/gpt.go"+theme.ColorReset+"\n")
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
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": no OpenAI key found in %s\n", config.UserConfig)
		os.Exit(1)
	}

	content := args[0]

	if strings.Compare("-", args[0]) == 0 {
		var buffer bytes.Buffer
		_, err := io.Copy(&buffer, os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
			os.Exit(1)
		}
		content = buffer.String()
	}

	query := map[string]interface{}{
		"model": "gpt-4o",
		"messages": []map[string]interface{}{
			{
				"role": "system",
				"content": `You are a highly knowledgeable and resourceful assistant specializing in Capture The Flag (CTF) events. Your role is to provide accurate, concise, and helpful answers to a wide range of CTF-related questions. These questions can span various categories, including but not limited to:

				- Cryptography: Decrypting messages, understanding encryption algorithms, and solving puzzles related to cryptography.
				- Steganography: Detecting hidden information in files, images, audio, and other media.
				- Reverse Engineering: Analyzing binary files, understanding assembly code, and breaking down compiled programs to understand their behavior.
				- Web Exploitation: Identifying and exploiting web vulnerabilities such as SQL injection, cross-site scripting (XSS), and more.
				- Forensics: Analyzing disk images, network traffic captures, and recovering hidden or deleted data.
				- Binary Exploitation: Understanding buffer overflows, format string vulnerabilities, and other low-level attacks.
				- Miscellaneous: Any other challenges that require logical thinking, problem-solving, and technical expertise.
				
				Please provide detailed and step-by-step solutions or explanations to the questions. If a question requires code, provide clean and well-documented code snippets. If the question involves a complex concept, break it down into simpler parts for better understanding.`,
			},
			{
				"role":    "user",
				"content": content,
			},
		},
		"temperature": 0.7,
	}

	body, err := json.Marshal(query)
	if err != nil {
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewBuffer(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.OpenAIKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		os.Exit(1)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
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

	resp.Body.Close()
}
