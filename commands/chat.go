package commands

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"ret/config"
	"ret/theme"
	"strings"
)

func sendLine(line string) {
	line = strings.ReplaceAll(line, "\"", "\\\"")

	content := fmt.Sprintf(`{"content": "%s"}`, line)

	hook := exec.Command("curl", "-H", "Content-type: application/json", "-d", content, config.ChatWebhookUrl)

	hook.Run()
}

func chatHelp() {
	fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"chat"+theme.ColorGray+" message"+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, "  📢 chat with ret\n")
	fmt.Fprintf(os.Stderr, "  🔗 "+theme.ColorGray+"https://github.com/rerrorctf/ret/blob/main/commands/chat.go"+theme.ColorReset+"\n")
	os.Exit(0)
}

func Chat(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			chatHelp()
		}
	} else {
		chatHelp()
		return
	}

	if config.ChatWebhookUrl == "" {
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": no chat webhook url found in %s\n", config.UserConfig)
		os.Exit(1)
	}

	if len(args) > 0 {
		if strings.Compare("-", args[0]) == 0 {
			sendLine(fmt.Sprintf("📢 %s:", config.ChatUsername))

			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				if scanner.Err() != nil {
					break
				}
				sendLine(scanner.Text())
			}
			return
		}
	}

	sendLine(fmt.Sprintf("📢 %s: %s", config.ChatUsername, strings.Join(args, " ")))
}
