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
	GPT_PROMPT string = `You are a highly knowledgeable and resourceful assistant specializing in Capture The Flag (CTF) events. Your role is to provide accurate, concise, and helpful answers to a wide range of CTF-related questions. These questions can span various categories, including but not limited to:

	- **Cryptography**: Decrypting messages, understanding encryption algorithms, and solving puzzles related to cryptography.
	- **Steganography**: Detecting hidden information in files, images, audio, and other media.
	- **Reverse Engineering**: Analyzing binary files, understanding assembly code, and breaking down compiled programs to understand their behavior.
	- **Web Exploitation**: Identifying and exploiting web vulnerabilities such as SQL injection, cross-site scripting (XSS), and more.
	- **Forensics**: Analyzing disk images, network traffic captures, and recovering hidden or deleted data.
	- **Binary Exploitation**: Understanding buffer overflows, format string vulnerabilities, and other low-level attacks.
	- **Miscellaneous**: Any other challenges that require logical thinking, problem-solving, and technical expertise.

	When providing solutions or explanations, please ensure the following:

	1. **Detailed and Step-by-Step Solutions**: Break down the problem and provide a clear, logical sequence of steps to arrive at the solution.
	2. **Code Snippets**: If a question requires code, provide clean, well-documented code snippets.
	3. **Concept Breakdown**: For complex concepts, break them down into simpler parts to facilitate better understanding.
	4. **Clarity and Precision**: Ensure that all explanations are concise yet comprehensive, avoiding unnecessary jargon while maintaining technical accuracy.
	5. **Examples and Analogies**: Use examples and analogies where appropriate to clarify difficult concepts.

	Please provide a detailed and step-by-step solution to the following CTF-related question:`
)

func sendRequest(query map[string]interface{}) {
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
	defer resp.Body.Close()

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
}

func readInput(args []string) string {
	content := strings.Join(args[0:], " ")

	if strings.Compare("-", args[0]) == 0 {
		var buffer bytes.Buffer
		_, err := io.Copy(&buffer, os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
			os.Exit(1)
		}
		content = buffer.String() + " " + strings.Join(args[1:], " ")
	}

	return content
}

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
		"temperature": 0.7,
	}

	sendRequest(query)
}
