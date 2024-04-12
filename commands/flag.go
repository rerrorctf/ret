package commands

import (
	"fmt"
	"os"
	"rctf/config"
	"rctf/theme"
)

func FlagHelp() {
	fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"flag"+theme.ColorGray+" format"+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, "  ⛳ set the current flag format regex with rctf\n")
	os.Exit(0)
}

func Flag(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			FlagHelp()
		}
	} else {
		fmt.Printf("current flag format: %v\n", config.FlagFormat)
		os.Exit(1)
	}

	fmt.Printf("old flag format: %v\n", config.FlagFormat)

	config.FlagFormat = args[0]

	config.WriteUserConfig()

	fmt.Printf("new flag format: %v\n", config.FlagFormat)
}
