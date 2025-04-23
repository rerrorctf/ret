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

func init() {
	Commands = append(Commands, Command{
		Name:      "writeup",
		Emoji:     "📝",
		Func:      Writeup,
		Help:      WriteupHelp,
		Arguments: nil,
		SeeAlso:   []string{"name", "category", "event", "remote", "description", "pwn", "capture"}})
}

func WriteupHelp() string {
	return "create a markdown writeup using a template with ret\n\n" +
		"the writeup will be saved in a file called `writeup.md`\n\n" +
		"if a file called `writeup.md` already exists the command will abort\n" +
		"there is a small window for a time-of-check/time-of-use race here - you have been warned!\n"
}

func Writeup(args []string) {
	filePath := "writeup.md"

	_, err := os.Stat(filePath)

	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", filePath)
	}

	event := util.GetCurrentTaskEvent()
	if len(event) == 0 {
		event = "https://ctftime.link.goes.here"
	}

	name := util.GetCurrentTaskName()
	if len(name) == 0 {
		name = "NAME"
	}

	category := util.GetCurrentTaskCategory()
	if len(category) == 0 {
		category = "CATEGORY"
	}

	description := util.GetCurrentTaskDescription()
	if len(description) == 0 {
		description = "DESCRIPTION"
	}

	ip := util.GetCurrentTaskIp()
	port := util.GetCurrentTaskPort()

	script, _ := os.ReadFile("./" + config.PwnScriptName)

	flag := util.GetCurrentTaskFlag()
	if len(flag) == 0 {
		flag = config.FlagFormat
	}

	username := config.Username
	if username == "" {
		username = "YOUR-NAME-GOES-HERE"
	}

	date := time.Now().Format("2006/01/02")

	template := fmt.Sprintf(
		"%s\n\n"+
			"# %s (%s)\n\n"+
			"%s\n\n"+
			"nc %s %d\n\n"+
			"## Solution\n\n"+
			"```python\n"+
			"%s"+
			"```\n\n"+
			"## Flag\n`%s`\n\n"+
			"%s %s\n", event, name, category, description, ip, port, script, flag, username, date)

	err = os.WriteFile(filePath, []byte(template), 0644)

	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": unable to write file \"%s\" %v\n", filePath, err)
	}
}
