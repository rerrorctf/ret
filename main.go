package main

import (
	"flag"
	"fmt"
	"os"

	"rctf/commands"
	"rctf/config"
)

func help() {
	fmt.Println("Usage: rctf [init/add/status]...")
}

func ensureDirectory(dirPath string) {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		if config.Verbose {
			fmt.Println("mkdir", dirPath)
		}
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			fmt.Println("error creating directory:", err)
			os.Exit(1)
		}
	}
}

func ensureSkeleton() {
	ensureDirectory(config.FolderName)
	ensureDirectory(config.FilesFolderName)
}

func main() {
	flag.BoolVar(&config.Verbose, "v", false, "enable verbose mode")

	flag.Parse()

	if flag.NArg() < 1 {
		help()
		os.Exit(1)
	}

	ensureSkeleton()

	// TODO add sub commands to output of -h/--help

	switch flag.Arg(0) {
	case "init":
		commands.Init(flag.Args()[1:])
	case "add":
		commands.Add(flag.Args()[1:])
	case "status":
		commands.Status(flag.Args()[1:])
	case "pwn":
		commands.Pwn(flag.Args()[1:])
	case "ghidra":
		commands.Ghidra(flag.Args()[1:])
	default:
		fmt.Println("Unknown command:", flag.Arg(0))
		os.Exit(1)
	}
}

// should have a .rctf lock file held while this tool runs
