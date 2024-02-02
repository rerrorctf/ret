package commands

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"rctf/config"
	"rctf/data"
	"rctf/theme"
)

func Writeup(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"writeup"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  📝 create a template for a task in a file called writeup.md with rctf\n")
			os.Exit(0)
		}
	}

	jsonData, err := os.ReadFile(config.TaskName)
	if err != nil {
		log.Fatalln("💥 "+theme.ColorRed+"error"+theme.ColorReset+": reading", err)
	}

	var task data.Task

	err = json.Unmarshal(jsonData, &task)
	if err != nil {
		log.Fatalln("💥 "+theme.ColorRed+"error"+theme.ColorReset+" unmarshalling json:", err)
	}

	filePath := "writeup.md"

	_, err = os.Stat(filePath)

	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", filePath)
	}

	template := fmt.Sprintf(
		"https://chal.link.goes.here\n\n"+
			"# %s (%s)\n\n"+
			"%s\n\n"+
			"## Solution\n\n"+
			"## Flag\n`flag{example}`\n",
		task.Name, task.Category, task.Description)

	err = os.WriteFile(filePath, []byte(template), 0644)

	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": unable to write file \"%s\" %v\n", filePath, err)
	}
}
