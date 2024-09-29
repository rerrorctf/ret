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
		Name:  "gist",
		Emoji: "🐙",
		Func:  Gist,
		Help:  GistHelp,
		Arguments: []Argument{
			{
				Name:     "file",
				Optional: false,
				List:     true,
			},
		}})
}

func GistHelp() string {
	return fmt.Sprintf("make private gists with ret\n") +
		fmt.Sprintf(theme.ColorGray+"specify the path of one or more files to upload"+theme.ColorReset+"\n")
}

func Gist(args []string) {
	if len(args) == 0 {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": expected 1 or more arguments\n")
	}

	if len(config.GistToken) == 0 {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": no gist token in ~/.config/ret\n")
	}

	files := map[string]interface{}{}

	for _, file := range args {
		buffer, err := os.ReadFile(file)
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		}

		splits := strings.Split(file, "/")
		filename := splits[len(splits)-1]

		files[filename] = map[string]interface{}{
			"content": string(buffer),
		}
	}

	fmt.Printf("%s\n", util.Gist(files))
}
