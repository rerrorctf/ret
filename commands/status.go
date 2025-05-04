package commands

import (
	"encoding/json"
	"fmt"
	"os"
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
		Arguments: nil,
		SeeAlso:   []string{"add", "init", "name", "category", "event", "capture"}})
}

func StatusHelp() string {
	return "displays the status for the current task with ret\n"
}

func Status(args []string) {
	name := util.GetCurrentTaskName()
	if len(name) > 0 {
		fmt.Printf("🏷️ "+theme.ColorCyan+"%s"+theme.ColorReset+"\n", name)
	}

	category := util.GetCurrentTaskCategory()
	if len(category) > 0 {
		fmt.Printf("😼 "+theme.ColorYellow+"%s"+theme.ColorReset+"\n", category)
	}

	event := util.GetCurrentTaskEvent()
	if len(event) > 0 {
		fmt.Printf("🗓️ "+theme.ColorGreen+"%s"+theme.ColorReset+"\n", event)
	}

	flag := util.GetCurrentTaskFlag()
	if len(flag) > 0 {
		fmt.Printf("🏁 "+theme.ColorPurple+"%s"+theme.ColorPurple+"\n", flag)
	}

	jsonData, err := os.ReadFile(config.RetFilesNames)
	if err == nil {
		var files data.Files

		err = json.Unmarshal(jsonData, &files)
		if err == nil {
			for idx, file := range files.Files {
				fmt.Printf(theme.ColorGray+"["+theme.ColorBlue+"%v"+theme.ColorGray+"]"+theme.ColorReset, idx)
				fmt.Printf(theme.ColorGreen+" %s ", file.Filename)
				fmt.Printf(theme.ColorReset+"%s\n", file.SHA256)
			}
		}
	}
}
