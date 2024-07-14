package commands

import (
	"fmt"
	"ret/config"
	"ret/theme"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "format",
		Emoji: "🔍",
		Func:  Format,
		Help:  FormatHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/format.go",
		Arguments: []Argument{
			{
				Name:     "regex",
				Optional: true,
				List:     false,
			},
		}})
}

func FormatHelp() string {
	return fmt.Sprintf("set the current flag format regex with ret\n")
}

func Format(args []string) {
	if len(args) == 0 {
		fmt.Printf(theme.ColorGray+"current flag format: "+theme.ColorReset+"%v"+theme.ColorReset+"\n", config.FlagFormat)
		return
	}

	fmt.Printf(theme.ColorGray+"old flag format: "+theme.ColorRed+"%v"+theme.ColorReset+"\n", config.FlagFormat)

	config.FlagFormat = args[0]

	config.WriteUserConfig()

	fmt.Printf(theme.ColorGray+"new flag format: "+theme.ColorGreen+"%v"+theme.ColorReset+"\n", config.FlagFormat)
}
