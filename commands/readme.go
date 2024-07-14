package commands

import (
	"fmt"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "readme",
		Emoji: "🖨️ ",
		Func:  Readme,
		Help:  ReadmeHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/readme.go",
	})
}

func ReadmeHelp() string {
	return fmt.Sprintf("make the readme with ret\n")
}

func Readme(args []string) {
	//
}
