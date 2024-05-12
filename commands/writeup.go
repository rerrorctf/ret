package commands

import (
	"fmt"
	"log"
	"os"
	"ret/config"
	"ret/theme"
)

func Writeup(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"writeup"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  📝 create a template for a task in a file called writeup.md with ret\n")
			fmt.Fprintf(os.Stderr, "  🔗 "+theme.ColorGray+"https://github.com/rerrorctf/ret/blob/main/commands/writeup.go"+theme.ColorReset+"\n")
			os.Exit(0)
		}
	}

	filePath := "writeup.md"

	_, err := os.Stat(filePath)

	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", filePath)
	}

	template := fmt.Sprintf(
		"https://chal.link.goes.here\n\n"+
			"# TASK-NAME (CATEGORY)\n\n"+
			"AUTHOR DATE\n\n"+
			"DESCRIPTION\n\n"+
			"## Solution\n\n"+
			"## Flag\n`%s`\n", config.FlagFormat)

	err = os.WriteFile(filePath, []byte(template), 0644)

	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": unable to write file \"%s\" %v\n", filePath, err)
	}
}
