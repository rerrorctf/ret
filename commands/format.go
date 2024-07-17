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
		},
		SeeAlso: []string{"add", "capture", "writeup"}})
}

func FormatHelp() string {
	return "set the current flag format regex with ret\n\n" +
		"the flag format is stored in " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + " using the " + theme.ColorYellow + "`\"flagformat\"`" + theme.ColorReset + " field\n\n" +
		"the flag format regex will be used to search for flags when adding files with the " + theme.ColorGreen + "`add`" + theme.ColorReset + " command\n"
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
