package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"rctf/config"
	"rctf/data"
	"rctf/theme"
)

func Status(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"status"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  👀 displays the status for the current task with rctf\n")
			os.Exit(0)
		}
	}

	jsonData, err := os.ReadFile(config.RctfFilesName)
	if err != nil {
		os.Exit(1)
	}

	var files data.Files

	err = json.Unmarshal(jsonData, &files)
	if err == nil {
		for idx, file := range files.Files {

			fmt.Printf(theme.ColorGray+"["+theme.ColorBlue+"%v"+theme.ColorGray+"]"+theme.ColorReset, idx)
			fmt.Printf(theme.ColorGreen+" %s ", file.Filename)
			fmt.Printf(theme.ColorReset+"%s\n", file.SHA256)

			fmt.Printf(theme.ColorGray+"  type:   "+theme.ColorReset+"%s\n", file.Type)
		}
	}
}
