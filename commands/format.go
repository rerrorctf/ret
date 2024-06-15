package commands

import (
	"fmt"
	"ret/config"
	"ret/theme"
)

func FormatHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "format" + theme.ColorGray + " [regex]" + theme.ColorReset + "\n")
	fmt.Printf("  🔍 set the current flag format regex with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/format.go" + theme.ColorReset + "\n")
}

func Format(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			FormatHelp()
			return
		}
	} else {
		fmt.Printf(theme.ColorGray+"current flag format: "+theme.ColorReset+"%v"+theme.ColorReset+"\n", config.FlagFormat)
		return
	}

	fmt.Printf(theme.ColorGray+"old flag format: "+theme.ColorRed+"%v"+theme.ColorReset+"\n", config.FlagFormat)

	config.FlagFormat = args[0]

	config.WriteUserConfig()

	fmt.Printf(theme.ColorGray+"new flag format: "+theme.ColorGreen+"%v"+theme.ColorReset+"\n", config.FlagFormat)
}
