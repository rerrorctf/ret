package commands

import (
	"fmt"
	"ret/theme"
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

func ReadmeHelp() {
	fmt.Printf("  🖨️  make the readme with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/readme.go" + theme.ColorReset + "\n")
}

func Readme(args []string) {
	//
}
