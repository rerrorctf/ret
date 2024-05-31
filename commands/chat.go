package commands

import (
	"fmt"
	"os"
	"os/exec"
	"ret/config"
	"ret/theme"
	"strings"
)

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

	msg := strings.Join(args, " ")

	fmt.Printf("📢 %s: %s\n", config.ChatUsername, msg)

	content := fmt.Sprintf(`{"content": "📢 %s: %s"}`, config.ChatUsername, msg)

	hook := exec.Command("curl", "-H", "Content-type: application/json", "-d", content, config.ChatWebhookUrl)

	err := hook.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}
}
