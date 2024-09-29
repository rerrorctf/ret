package commands

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"ret/config"
	"ret/theme"
	"ret/util"
	"strings"
	"time"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "gpt",
		Emoji: "🧠",
		Func:  Gpt,
		Help:  GptHelp,
		Arguments: []Argument{
			{
				Name:     "-",
				Optional: true,
				List:     false,
			},
			{
				Name:     "question",
				Optional: true,
				List:     true,
			},
		}})
}

func GptHelp() string {
	return fmt.Sprintf("ask ChatGPT with ret\n") +
		fmt.Sprintf(theme.ColorGray+"use - to read from stdin"+theme.ColorReset+"\n")
}

const (
	GPT_COMMAND_PROMPT string = `You are a CTF assistant specializing in various categories:

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

func gptSpinner(stop chan bool) {
	emojis := []string{
		"🧠", "🤖", "💻", "🌐", "🔍", "📚", "🔬", "🚀", "🔮", "🚩",
	}

	for {
		for _, e := range emojis {
			select {
			case <-stop:
				return
			default:
				fmt.Printf("\r%s", e)
				time.Sleep(200 * time.Millisecond)
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
			log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		}
		content = buffer.String() + " " + strings.Join(args[1:], " ")
	}

	return content
}

func Gpt(args []string) {
	if len(args) == 0 {
		log.Fatalf("💥 " + theme.ColorRed + " error" + theme.ColorReset + ": expected 1 or more arguments\n")
		return
	}

	if config.OpenAIKey == "" {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": no OpenAI key found in %s\n", config.UserConfig)
	}

	content := readInput(args)

	fmt.Printf("🧠 " + theme.ColorGray + config.OpenAIModel + theme.ColorReset + "\n")

	stop := make(chan bool)

	go gptSpinner(stop)

	answer := util.Gpt(GPT_COMMAND_PROMPT, content)

	stop <- true

	fmt.Printf("\r")

	fmt.Printf("%s\n", answer)
}
