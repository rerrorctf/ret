package commands

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"ret/config"
	"ret/data"
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
		SeeAlso:   []string{"notes", "pwn", "capture", "ctftime"}})
}

func WriteupHelp() string {
	return "create a markdown writeup using a template with ret\n\n" +
		"the writeup will be saved in a file called `writeup.md`\n\n" +
		"if a file called `writeup.md` already exists the command will abort\n" +
		"there is a small window for a time-of-check/time-of-use race here - you have been warned!\n\n" +
		"1. uses the first url from " + theme.ColorYellow + "`\"ctftimeurls\"`" + theme.ColorReset + " to insert a url at the top of the writeup. inserts the rest as comments if there are more than one\n" +
		"2. imports all notes taken with the " + theme.ColorGreen + "`notes`" + theme.ColorReset + " command into the description area\n" +
		"3. creates a space for a python script and then imports the script created by " + theme.ColorGreen + "`pwn`" + theme.ColorReset + " if it exists\n" +
		"4. imports the flag captured with the " + theme.ColorGreen + "`capture`" + theme.ColorReset + " command if it exists\n" +
		"5. uses the " + theme.ColorYellow + "`\"username\"`" + theme.ColorReset + " from " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + " to attribute to this writeup to you\n" +
		"6. inserts a date stamp for today's date using yyyy/mm/dd format\n"
}

func Writeup(args []string) {
	filePath := "writeup.md"

	_, err := os.Stat(filePath)

	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", filePath)
	}

	urls := ""
	if len(config.CtfTimeUrls) > 0 {
		urls = config.CtfTimeUrls[0]
	}

	for _, ctfTimeUrl := range config.CtfTimeUrls[1:] {
		urls += "\n<!-- " + ctfTimeUrl + " -->"
	}

	if urls == "" {
		urls = "https://ctftime.link.goes.here"
	}

	flag := util.GetCurrentTaskFlag()
	if len(flag) == 0 {
		flag = config.FlagFormat
	}

	notesStr := ""

	jsonData, err := os.ReadFile(config.NotesFileName)
	if err == nil {
		var notes data.Notes
		err = json.Unmarshal(jsonData, &notes)
		if err == nil {
			for _, note := range notes.Notes {
				notesStr += fmt.Sprintf("%s\n\n", note.Note)
			}
		}

	}

	script, _ := os.ReadFile("./" + config.PwnScriptName)

	name := config.Username
	if name == "" {
		name = "YOUR-NAME-GOES-HERE"
	}

	date := time.Now().Format("2006/01/02")

	template := fmt.Sprintf(
		"%s\n\n"+
			"# NAME (CATEGORY)\n\n"+
			"%s"+
			"## Solution\n\n"+
			"```python\n"+
			"%s"+
			"```\n\n"+
			"## Flag\n`%s`\n\n"+
			"%s %s\n", urls, notesStr, script, flag, name, date)

	err = os.WriteFile(filePath, []byte(template), 0644)

	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": unable to write file \"%s\" %v\n", filePath, err)
	}
}
