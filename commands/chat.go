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
	return message
}

func sendMessage(message map[string]interface{}) {
	body, err := json.Marshal(message)
	if err != nil {
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	req, err := http.NewRequest("POST", config.ChatWebhookUrl, bytes.NewBuffer(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	resp.Body.Close()
}

func sendChat(message string) {
	message = removeColors(message)

	body := map[string]interface{}{
		"username": config.ChatUsername,
		"content":  message,
	}

	sendMessage(body)
}

func sendEmbed(message string) {
	message = removeColors(message)

	embed := map[string]interface{}{
		//"title": "ret chat",
		//"description": "This is an example of a rich embed.",
		//"url":       "https://github.com/rerrorctf/ret/blob/main/commands/chat.go",
		"color":     rand.Intn(0xFFFFFF),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		//"footer": map[string]string{
		//"text":     "https://github.com/rerrorctf/ret/blob/main/commands/chat.go",
		//"icon_url": "https://example.com/footer-icon.png",
		//},
		//"thumbnail": map[string]string{
		//"url": "https://example.com/thumbnail.png",
		//},
		//"image": map[string]string{
		//"url": "https://example.com/image.png",
		//},
		//"author": map[string]string{
		//"name":     "Author Name",
		//"url":      "https://example.com",
		//"icon_url": "https://example.com/author-icon.png",
		//},
		"fields": []map[string]interface{}{
			{
				"name":   "ret chat 📢",
				"value":  message,
				"inline": false,
			},
		},
	}

	body := map[string]interface{}{
		"username": config.ChatUsername,
		"embeds":   []interface{}{embed},
	}

	sendMessage(body)
}

func chatHelp() {
	fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"chat"+theme.ColorGray+" message"+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, "  📢 chat with ret\n")
	fmt.Fprintf(os.Stderr, "     "+theme.ColorGray+"use - to read from stdin"+theme.ColorReset+"\n")
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
			var buffer bytes.Buffer
			_, err := io.Copy(&buffer, os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
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
