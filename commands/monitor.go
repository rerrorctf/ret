package commands

import (
	"fmt"
	"os"
	"rctf/theme"
)

func Monitor(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"monitor"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  📡 watch infra for up/down state changes with rctf\n")

			os.Exit(0)
		}
	}

	// TODO
}
