package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"ret/config"
	"ret/theme"
	"strings"
	"time"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "chat",
		Emoji: "📢",
		Func:  Chat,
		Help:  ChatHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/chat.go",
		Arguments: []Argument{
			{
				Name:     "-",
				Optional: true,
				List:     false,
			},
			{
				Name:     "message",
				Optional: true,
				List:     true,
			},
		}})
}

func ChatHelp() string {
	return fmt.Sprintf("chat with ret\n") +
		fmt.Sprintf(theme.ColorGray+"use - to read from stdin"+theme.ColorReset+"\n")
}

func sendMessage(message map[string]interface{}) {
	body, err := json.Marshal(message)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	req, err := http.NewRequest("POST", config.ChatWebhookUrl, bytes.NewBuffer(body))
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	resp.Body.Close()
}

func sendChat(message string) {
	message = theme.RemoveColors(message)

	body := map[string]interface{}{
		"username": config.Username,
		"content":  message,
	}

	sendMessage(body)
}

func sendEmbed(message string) {
	message = theme.RemoveColors(message)

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

func Chat(args []string) {
	if len(args) == 0 {
		log.Fatalf("💥 " + theme.ColorRed + " error" + theme.ColorReset + ": expected 1 or more arguments\n")
	}

	if config.ChatWebhookUrl == "" {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": no chat webhook url found in %s\n", config.UserConfig)
	}

	if config.Username == "" {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": no username found in %s\n", config.UserConfig)
	}

	if len(args) > 0 {
		if strings.Compare("-", args[0]) == 0 {
			var buffer bytes.Buffer
			_, err := io.Copy(&buffer, os.Stdin)
			if err != nil {
				log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
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
