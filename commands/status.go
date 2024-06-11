package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"ret/config"
	"ret/data"
	"ret/theme"
)

func Status(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "status" + theme.ColorReset + "\n")
			fmt.Printf("  👀 displays the status for the current task with ret\n")
			fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/status.go" + theme.ColorReset + "\n")
			os.Exit(0)
		}
	}

	jsonData, err := os.ReadFile(config.RetFilesNames)
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

			if file.FileType == data.FILE_TYPE_ELF {
				checksec := exec.Command("pwn", "checksec", file.Filepath)

				checksec.Stdout = os.Stdout
				checksec.Stderr = os.Stderr
				checksec.Stdin = os.Stdin

				err := checksec.Run()
				if err != nil {
					fmt.Printf(theme.ColorGray+"    "+theme.ColorReset+"%s\n", file.FileOutput)
					continue
				}
			} else {
				fmt.Printf(theme.ColorGray+"    "+theme.ColorReset+"%s\n", file.FileOutput)
			}
		}
	}
}
