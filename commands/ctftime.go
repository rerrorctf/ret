package commands

import (
	"fmt"
	"ret/config"
	"ret/theme"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "ctftime",
		Emoji: "🚩",
		Func:  CtfTime,
		Help:  CtfTimeHelp,
		Arguments: []Argument{
			{
				Name:     "url",
				Optional: true,
				List:     false,
			},
		},
		SeeAlso: []string{"writeup"}})
}

func CtfTimeHelp() string {
	return "set the current ctftime url with ret\n\n" +
		"the ctftime url is stored in " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + " using the " + theme.ColorYellow + "`\"ctftimeurl\"`" + theme.ColorReset + " field\n\n" +
		"the ctftime url will be used to aid in the generation of writeups with the " + theme.ColorGreen + "`writeup`" + theme.ColorReset + " command\n"
}

func CtfTime(args []string) {
	if len(args) == 0 {
		fmt.Printf(theme.ColorGray+"current ctftime url: "+theme.ColorReset+"%v"+theme.ColorReset+"\n", config.CtfTimeUrl)
		return
	}

	fmt.Printf(theme.ColorGray+"old ctftime url: "+theme.ColorRed+"%v"+theme.ColorReset+"\n", config.CtfTimeUrl)

	config.CtfTimeUrl = args[0]

	config.WriteUserConfig()

	fmt.Printf(theme.ColorGray+"new ctftime url: "+theme.ColorGreen+"%v"+theme.ColorReset+"\n", config.CtfTimeUrl)
}
