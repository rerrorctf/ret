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
		Url:       "https://github.com/rerrorctf/ret/blob/main/commands/wizard.go",
		Arguments: nil,
		SeeAlso:   []string{"notes", "pwn", "capture", "format", "ctftime"}})
}

func WriteupHelp() string {
	return "create a markdown writeup using a template with ret\n\n" +
		"the writeup will saved in a file called `writeup.md`\n\n" +
		"if a file called `writeup.md` already exists the command will abort\n\n" +
		"1. uses the " + theme.ColorYellow + "`\"ctftimeurl\"`" + theme.ColorReset + " to insert a url at the top of the writeup\n" +
		"2. imports all notes taken with the " + theme.ColorGreen + "`notes`" + theme.ColorReset + " command into the description area\n" +
		"3. creates a space for a python script and then imports the script created by " + theme.ColorGreen + "`pwn`" + theme.ColorReset + " if one exists\n" +
		"4. imports the flag captured with the " + theme.ColorGreen + "`capture`" + theme.ColorReset + " command if one exists or the regex specfied with " + theme.ColorGreen + "`format`" + theme.ColorReset + " if one does not\n" +
		"5. uses the " + theme.ColorYellow + "`\"username\"`" + theme.ColorReset + " from " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + " to attribute to this writeup to you\n" +
		"6. inserts a date stamp for today's date using yyyy/mm/dd format\n"
}

func Writeup(args []string) {
	filePath := "writeup.md"

	_, err := os.Stat(filePath)

	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", filePath)
	}

	url := config.CtfTimeUrl
	if url == "" {
		url = "https://ctftime.link.goes.here"
	}

	flag, err := util.GetCurrentFlag()
	if err != nil {
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
			"%s %s\n", url, notesStr, script, flag, name, date)

	err = os.WriteFile(filePath, []byte(template), 0644)

	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": unable to write file \"%s\" %v\n", filePath, err)
	}
}
