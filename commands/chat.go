package commands

import (
	"bytes"
	"encoding/json"
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
	return "chat via a discord webhook with ret\n\n" +
		"use - to read from stdin\n\n" +
		"requires that " + theme.ColorYellow + "`\"chatwebhookurl\"`" + theme.ColorReset + " from " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + " is a valid webhook\n\n" +
		"requires that " + theme.ColorYellow + "`\"username\"`" + theme.ColorReset + " from " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + " is set to valid string\n\n" +
		"when data is read from stdin, due to the use of the - argument, it will be sent as an embed with an accurate timestamp and a random color\n\n" +
		"color codes, such as the ones used by this tool, are stripped by this code prior to sending\n\n" +
		"for more information please see " + theme.ColorPurple + "https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks\n" + theme.ColorReset
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
