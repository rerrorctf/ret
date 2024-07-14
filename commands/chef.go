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

func ChefHelp() {
	fmt.Printf("  🔪 open cyberchef with ret\n")
	fmt.Printf("     " + theme.ColorGray + "use file - to read from stdin" + theme.ColorReset + "\n")
}

func Chef(args []string) {
	if len(args) == 0 {
		ChefHelp()
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
