package commands

import (
	"fmt"
	"os"
	"rctf/theme"
)

func Check(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"check"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  ✅ check your env/setup readiness before a ctf with rctf\n")

			os.Exit(0)
		}
	}

	// TODO
}
