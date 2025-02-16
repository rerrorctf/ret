package commands

import (
	"fmt"
	"os"
	"ret/config"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:      "share",
		Emoji:     "🌐",
		Func:      Share,
		Help:      ShareHelp,
		Arguments: nil,
		SeeAlso:   []string{"notes", "capture", "chat", "gist", "pwn", "crypto"}})
}

func ShareHelp() string {
	return "share task progress with ret\n\n" +
		"if you have captured a flag with the " + theme.ColorGreen + "`capture`" + theme.ColorReset + " command this will be sent using the " + theme.ColorGreen + "`chat`" + theme.ColorReset + " command\n\n" +
		"if you have a valid " + theme.ColorYellow + "`\"gisttoken\"`" + theme.ColorReset + " this command will also make a gist and include the url in the chat message\n\n" +
		"the gist will attempt to include the following files:\n\n" +
		"1. the pwn script, which uses " + theme.ColorYellow + "`\"pwnscriptname\"`" + theme.ColorReset + ", and is typically generated with the " + theme.ColorGreen + "`pwn`" + theme.ColorReset + " command\n" +
		"2. the crypto script, which uses " + theme.ColorYellow + "`\"cryptoscriptname\"`" + theme.ColorReset + ", and is typically generated with the " + theme.ColorGreen + "`crypto`" + theme.ColorReset + " command\n" +
		"3. the notes, which are saved in the " + theme.ColorCyan + ".ret/notes.json" + theme.ColorReset + " file, and are typically populated with the " + theme.ColorGreen + "`notes`" + theme.ColorReset + " command\n" +
		"4. the flag, which is saved in the " + theme.ColorCyan + ".ret/flag.json" + theme.ColorReset + " file, and is typically set with the " + theme.ColorGreen + "`capture`" + theme.ColorReset + " command\n"
}

func Share(args []string) {
	flag, err := util.GetCurrentFlag()
	if err != nil {
		flag = config.FlagFormat
	}

	gistUrl := ""

	if len(config.GistToken) > 0 {
		files := map[string]interface{}{}

		buffer, err := os.ReadFile(config.PwnScriptName)
		if err == nil {
			files[config.PwnScriptName] = map[string]interface{}{
				"content": string(buffer),
			}
		}

		buffer, err = os.ReadFile(config.CryptoScriptName)
		if err == nil {
			files[config.CryptoScriptName] = map[string]interface{}{
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

		if len(files) > 0 {
			gistUrl = "**" + util.Gist(files) + "**"
		}
	}

	Chat([]string{fmt.Sprintf("🏁 `%s`\n%s", flag, gistUrl)})
}
