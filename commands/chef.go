package commands

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"ret/theme"
	"strings"
)

const (
	CHEF_URL = "https://gchq.github.io/CyberChef/#input="
)

func init() {
	Commands = append(Commands, Command{
		Name:  "chef",
		Emoji: "🔪",
		Func:  Chef,
		Help:  ChefHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/chef.go",
		Arguments: []Argument{
			{
				Name:     "-",
				Optional: true,
				List:     false,
			},
			{
				Name:     "text",
				Optional: true,
				List:     true,
			},
		}})
}

func ChefHelp() string {
	return "open cyberchef with ret\n\n" +
		"use file - to read from stdin\n\n" +
		"for example:\n" +
		"```bash\n" +
		theme.ColorGray + "$ " + theme.ColorBlue + "echo \"hello, world!\" | base64 | ret chef -\n" + theme.ColorReset +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret chef aHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQ==\n" + theme.ColorReset +
		"```\n\n" +
		fmt.Sprintf("generates a cyberchef url by appending your input, raw base64 encoded, to "+theme.ColorPurple+"%s"+theme.ColorReset+"\n\n", CHEF_URL) +
		"uses " + theme.ColorGreen + "`open`" + theme.ColorReset + " to open the resulting url in your default browser\n"
}

func Chef(args []string) {
	if len(args) == 0 {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": expected 1 or more arguments\n")
		return
	}

	input := ""
	if strings.Compare("-", args[0]) == 0 {
		var buffer bytes.Buffer
		_, err := io.Copy(&buffer, os.Stdin)
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
		}

		input += buffer.String()
		input += strings.Join(args[1:], " ")
	} else {
		input += strings.Join(args, " ")
	}

	encoded := base64.RawStdEncoding.EncodeToString([]byte(input))

	finalUrl := CHEF_URL + encoded

	fmt.Printf("%s\n", finalUrl)

	open := exec.Command("open", finalUrl)

	err := open.Run()
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}
