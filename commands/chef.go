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
	URL = "https://gchq.github.io/CyberChef/#input="
)

func chefHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "chef" + theme.ColorGray + " [-] [text]" + theme.ColorReset + "\n")
	fmt.Printf("  🔪 open cyberchef with ret\n")
	fmt.Printf("     " + theme.ColorGray + "use file - to read from stdin" + theme.ColorReset + "\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/chef.go" + theme.ColorReset + "\n")
}

func Chef(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			chefHelp()
			return
		}
	} else {
		chefHelp()
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

	finalUrl := URL + encoded

	fmt.Printf("%s\n", finalUrl)

	open := exec.Command("open", finalUrl)

	err := open.Run()
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}
