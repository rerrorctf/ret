package commands

import (
	"fmt"
	"log"
	"os"
	"ret/config"
	"ret/theme"
	"ret/util"
	"time"
)

func Writeup(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "writeup" + theme.ColorReset + "\n")
			fmt.Printf("  📝 create a template for a task in a file called writeup.md with ret\n")
			fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/writeup.go" + theme.ColorReset + "\n")
			os.Exit(0)
		}
	}

	filePath := "writeup.md"

	_, err := os.Stat(filePath)

	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", filePath)
	}

	flag, err := util.GetCurrentFlag()
	if err != nil {
		flag = config.FlagFormat
	}

	script, _ := os.ReadFile("./" + config.PwnScriptName)

	name := config.Username
	if name == "" {
		name = "YOUR-NAME-GOES-HERE"
	}

	date := time.Now().Format("2006/01/02")

	template := fmt.Sprintf(
		"https://chal.link.goes.here\n\n"+
			"# TASK-NAME (CATEGORY)\n\n"+
			"DESCRIPTION-GOES-HERE\n\n"+
			"## Solution\n\n"+
			"```python\n"+
			"%s"+
			"```\n\n"+
			"## Flag\n`%s`\n\n"+
			"%s %s\n", script, flag, name, date)

	err = os.WriteFile(filePath, []byte(template), 0644)

	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": unable to write file \"%s\" %v\n", filePath, err)
	}
}
