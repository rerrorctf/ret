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
	return "remove a ctf with ret\n\n"
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
