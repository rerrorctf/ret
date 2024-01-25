package commands

import (
	"fmt"
	"os"
	"rctf/config"
)

func GhidraHelp() {
	fmt.Println("rctf ghidra help would go here...")
}

func Ghidra(args []string) {
	if config.Verbose {
		fmt.Println("Ghidra:", args)
	}

	if len(args) > 0 {
		switch args[0] {
		case "help":
			GhidraHelp()
			os.Exit(0)
		}
	}
}
