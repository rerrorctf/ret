package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"ret/config"
	"ret/theme"
	"strings"
	"time"
)

func removeColors(message string) string {
	message = strings.ReplaceAll(message, theme.ColorReset, "")
	message = strings.ReplaceAll(message, theme.ColorRed, "")
	message = strings.ReplaceAll(message, theme.ColorGreen, "")
	message = strings.ReplaceAll(message, theme.ColorYellow, "")
	message = strings.ReplaceAll(message, theme.ColorBlue, "")
	message = strings.ReplaceAll(message, theme.ColorPurple, "")
	message = strings.ReplaceAll(message, theme.ColorCyan, "")
	message = strings.ReplaceAll(message, theme.ColorGray, "")
	message = strings.ReplaceAll(message, theme.StartUnderline, "")
	message = strings.ReplaceAll(message, theme.StopUnderline, "")
	return message
}

func sendMessage(message map[string]interface{}) {
	body, err := json.Marshal(message)
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	req, err := http.NewRequest("POST", config.ChatWebhookUrl, bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	resp.Body.Close()
}

func sendChat(message string) {
	message = removeColors(message)

	body := map[string]interface{}{
		"username": config.Username,
		"content":  message,
	}

	sendMessage(body)
}

func sendEmbed(message string) {
	message = removeColors(message)

	embed := map[string]interface{}{
		"color":     rand.Intn(0xFFFFFF),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"fields": []map[string]interface{}{
			{
				"name":   "ret chat 📢",
				"value":  message,
				"inline": false,
			},
		},
	}

	body := map[string]interface{}{
		"username": config.Username,
		"embeds":   []interface{}{embed},
	}

	sendMessage(body)
}

func chatHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "chat" + theme.ColorGray + " message" + theme.ColorReset + "\n")
	fmt.Printf("  📢 chat with ret\n")
	fmt.Printf("     " + theme.ColorGray + "use - to read from stdin" + theme.ColorReset + "\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/chat.go" + theme.ColorReset + "\n")
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
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": no chat webhook url found in %s\n", config.UserConfig)
		os.Exit(1)
	}

	if len(args) > 0 {
		if strings.Compare("-", args[0]) == 0 {
			var buffer bytes.Buffer
			_, err := io.Copy(&buffer, os.Stdin)
			if err != nil {
				fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
				os.Exit(1)
			}
			sendEmbed(buffer.String())

			if len(args) > 1 {
				sendChat(strings.Join(args[1:], " "))
			}

			return
		}
	}

	sendChat(strings.Join(args, " "))
}
