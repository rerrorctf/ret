package commands

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"ret/config"
	"ret/theme"
	"strings"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "chef",
		Emoji: "🔪",
		Func:  Chef,
		Help:  ChefHelp,
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
		"generates a cyberchef url by appending your input, raw base64 encoded, to " + theme.ColorPurple + "https://gchq.github.io/CyberChef/#input=" + theme.ColorReset + "\n\n" +
		"you can set " + theme.ColorYellow + "`\"chefurl\"`" + theme.ColorReset + " in " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + " to use another instance of cyberchef\n\n" +
		"if you provide a custom url it should be the equivalent of " + theme.ColorPurple + "https://gchq.github.io/CyberChef/" + theme.ColorReset + "\n"
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

	finalUrl := config.ChefUrl + "#input=" + encoded

	fmt.Printf("%s\n", finalUrl)
}
