package commands

import (
	"fmt"
	"log"
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
		SeeAlso:   []string{"notes", "capture", "chat", "gist", "pwn"}})
}

func ShareHelp() string {
	return "share task progress with ret\n\n"
}

func Share(args []string) {
	if len(config.GistToken) == 0 {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": no gist token in ~/.config/ret\n")
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

	flag, err := util.GetCurrentFlag()
	if err != nil {
		flag = config.FlagFormat
	} else {
		files["flag.txt"] = map[string]interface{}{
			"content": string(flag),
		}
	}

	gistUrl := ""
	if len(files) > 0 {
		gistUrl = "**" + util.Gist(files) + "**"
	}

	Chat([]string{fmt.Sprintf("🏁 `%s`\n%s", flag, gistUrl)})
}
