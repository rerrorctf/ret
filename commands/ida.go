package commands

import (
	"fmt"
	"os"
)

func Ida(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
			fmt.Fprintf(os.Stderr, "usage: rctf ida\n")

			fmt.Fprintf(os.Stderr, "  💃 ingests all added files then opens ida with rctf\n")

			fmt.Fprintf(os.Stderr, "\nsubcommands:\n")
			fmt.Fprintf(os.Stderr, "  ❓ help ~ print this message\n")

			fmt.Fprintf(os.Stderr, "\n~ 🚩 @rerrorctf 🚩 ~\n")
			fmt.Fprintf(os.Stderr, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

			os.Exit(0)
		}
	}

	fmt.Println("💃 this might take a while...")

	// TODO
}
