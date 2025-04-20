package commands

import (
	"fmt"
	"log"
	"os"
	"ret/config"
	"ret/theme"
	"ret/util"
	"strings"
)

func init() {
	Commands = append(Commands, Command{
		Name:      "share",
		Emoji:     "🌐",
		Func:      Share,
		Help:      ShareHelp,
		Arguments: nil,
		SeeAlso:   []string{"notes", "capture", "chat", "gist", "pwn"}})
}

func ShareHelp() string {
	return "share task progress with ret\n\n" +
		"if you have captured a flag with the " + theme.ColorGreen + "`capture`" + theme.ColorReset + " command this will be sent using the " + theme.ColorGreen + "`chat`" + theme.ColorReset + " command\n\n" +
		"if you have a valid " + theme.ColorYellow + "`\"gisttoken\"`" + theme.ColorReset + " this command will also make a gist and include the url in the chat message\n\n" +
		"the gist will attempt to include the following files:\n\n" +
		"1. the pwn script, which uses " + theme.ColorYellow + "`\"pwnscriptname\"`" + theme.ColorReset + ", and is typically generated with the " + theme.ColorGreen + "`pwn`" + theme.ColorReset + " command\n" +
		"2. the notes, which are saved in the " + theme.ColorCyan + ".ret/notes.json" + theme.ColorReset + " file, and are typically populated with the " + theme.ColorGreen + "`notes`" + theme.ColorReset + " command\n" +
		"3. the flag, which is saved in the " + theme.ColorCyan + ".ret/task.json" + theme.ColorReset + " file, and is typically set with the " + theme.ColorGreen + "`capture`" + theme.ColorReset + " command\n"
}

func Share(args []string) {
	path, err := os.Getwd()
	if err != nil {
		log.Fatalln("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v", err)
	}

	splits := strings.Split(path, "/")
	dir := splits[len(splits)-1]

	flag := util.GetCurrentTaskFlag()
	if len(flag) == 0 {
		flag = config.FlagFormat
	}

	gistUrl := ""

	if len(config.GistToken) == 0 {
		Chat([]string{fmt.Sprintf("🏁 `%s` **%s**", flag, dir)})
		return
	}

	files := map[string]interface{}{}

	buffer, err := os.ReadFile(config.PwnScriptName)
	if err == nil {
		files[config.PwnScriptName] = map[string]interface{}{
			"content": string(buffer),
		}
	}

	buffer, err = os.ReadFile(config.NotesFileName)
	if err == nil {
		// does not like .ret/notes.json
		files["notes.json"] = map[string]interface{}{
			"content": string(buffer),
		}
	}

	files["flag.txt"] = map[string]interface{}{
		"content": string(flag),
	}

	files["path.txt"] = map[string]interface{}{
		"content": path,
	}

	if len(files) > 0 {
		gistUrl = util.Gist(files)
	}

	Chat([]string{fmt.Sprintf("🏁 `%s` **[%s](%s)**", flag, dir, gistUrl)})
}
