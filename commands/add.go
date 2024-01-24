package commands

import (
	"fmt"
	"os"
)

func AddHelp() {
	fmt.Println("rctf add help would go here...")
}

func Add(args []string) {
	fmt.Println("Add:", args)

	if len(args) > 0 {
		switch args[0] {
		case "help":
			AddHelp()
			os.Exit(0)
		}
	}
}
