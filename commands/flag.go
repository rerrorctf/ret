package commands

import (
	"fmt"
	"os"
	"ret/config"
	"ret/theme"
)

func FlagHelp() {
	fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"flag"+theme.ColorGray+" format"+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, "  ⛳ set the current flag format regex with ret\n")
	os.Exit(0)
}

func Flag(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			FlagHelp()
		}
	} else {
		fmt.Printf(theme.ColorGray+"current flag format: "+theme.ColorReset+"%v"+theme.ColorReset+"\n", config.FlagFormat)
		os.Exit(1)
	}

	fmt.Printf(theme.ColorGray+"old flag format: "+theme.ColorRed+"%v"+theme.ColorReset+"\n", config.FlagFormat)

	config.FlagFormat = args[0]

	config.WriteUserConfig()

	fmt.Printf(theme.ColorGray+"new flag format: "+theme.ColorGreen+"%v"+theme.ColorReset+"\n", config.FlagFormat)
}
