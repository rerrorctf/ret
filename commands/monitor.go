package commands

import (
	"fmt"
	"os"
)

func Monitor(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, "usage: rctf monitor\n")
			fmt.Fprintf(os.Stderr, "  📡 watch infra for up/down state changes with rctf\n")

			os.Exit(0)
		}
	}

	// TODO
}
