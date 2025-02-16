package commands

import (
	"fmt"
	"os"
	"ret/config"
	"ret/util"
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
	return "share task progress with ret\n\n"
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
