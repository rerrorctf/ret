package commands

import (
	"fmt"
	"log"
	"ret/config"
	"ret/theme"
	"strings"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "ctfrm",
		Emoji: "🚮",
		Func:  Ctfrm,
		Help:  CtfrmHelp,
		Arguments: []Argument{
			{
				Name:     "url",
				Optional: true,
				List:     false,
			},
		},
		SeeAlso: []string{"ctftime", "writeup"}})
}

func CtfrmHelp() string {
	return "remove a ctf with ret\n\n" +
		"the ctftime url will be removed from the list, if it exists in the list, that is stored in " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + " in the " + theme.ColorYellow + "`\"ctftimeurls\"`" + theme.ColorReset + "\n\n" +
		"you can also manually remove ctftime urls from this list by directly editing " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + "\n"
}

func Ctfrm(args []string) {
	if len(args) > 0 {
		ctfTimeUrlToRemove := strings.Trim(args[0], "/")

		for idx, ctfTimeUrl := range config.CtfTimeUrls {
			if ctfTimeUrlToRemove == ctfTimeUrl {
				config.CtfTimeUrls = append(config.CtfTimeUrls[:idx], config.CtfTimeUrls[idx+1:]...)
				config.WriteUserConfig()
				fmt.Printf(theme.ColorGray+"removed ctftime url: "+theme.ColorRed+"%v"+theme.ColorRed+"\n", ctfTimeUrlToRemove)
				return
			}
		}

		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": no ctf with the url %v has been registered\n", ctfTimeUrlToRemove)
		return
	}
}
