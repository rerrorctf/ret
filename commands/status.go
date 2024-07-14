package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"ret/config"
	"ret/data"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:      "status",
		Emoji:     "👀",
		Func:      Status,
		Help:      StatusHelp,
		Url:       "https://github.com/rerrorctf/ret/blob/main/commands/status.go",
		Arguments: nil})
}

func StatusHelp() {
	fmt.Printf("  👀 displays the status for the current task with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/status.go" + theme.ColorReset + "\n")
}

func Status(args []string) {
	jsonData, err := os.ReadFile(config.RetFilesNames)
	if err == nil {
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
						fileOutput := util.RunFileCommandOnFile(file.Filepath)
						fmt.Printf(theme.ColorGray+"    "+theme.ColorReset+"%s\n", fileOutput)
						continue
					}
				} else {
					fileOutput := util.RunFileCommandOnFile(file.Filepath)
					fmt.Printf(theme.ColorGray+"    "+theme.ColorReset+"%s\n", fileOutput)
				}
			}
		}
	}

	flag, err := util.GetCurrentFlag()
	if err == nil {
		fmt.Printf("🚩 "+theme.ColorPurple+"%s"+theme.ColorPurple+"\n", flag)
	} else if config.FlagFormat != "" {
		fmt.Printf("🔍 "+theme.ColorPurple+"%s"+theme.ColorPurple+"\n", config.FlagFormat)
	}
}
