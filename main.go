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

func ensureSkeleton() {
	if _, err := os.Stat(config.FolderName); os.IsNotExist(err) {
		fmt.Println("mkdir", config.FolderName)
		err := os.MkdirAll(config.FolderName, 0755)
		if err != nil {
			fmt.Println("error creating directory:", err)
			os.Exit(1)
		}
	}

	if _, err := os.Stat(config.FilesFolderName); os.IsNotExist(err) {
		fmt.Println("mkdir", config.FilesFolderName)
		err := os.MkdirAll(config.FilesFolderName, 0755)
		if err != nil {
			fmt.Println("error creating directory:", err)
			os.Exit(1)
		}
	}

	if _, err := os.Stat(config.FolderName + "/ghidra"); os.IsNotExist(err) {
		fmt.Println("mkdir", config.FolderName+"/ghidra")
		err := os.MkdirAll(config.FolderName+"/ghidra", 0755)
		if err != nil {
			fmt.Println("error creating directory:", err)
			os.Exit(1)
		}
	}
}

func main() {
	ensureSkeleton()

	var verbose bool
	flag.BoolVar(&verbose, "v", false, "enable verbose mode")

	flag.Parse()

	if flag.NArg() < 1 {
		help()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		commands.Init(os.Args[2:])
	case "add":
		commands.Add(os.Args[2:])
	case "status":
		commands.Status(os.Args[2:])
	default:
		fmt.Println("Unknown command:", os.Args[1])
		os.Exit(1)
	}
}

// should have a .rctf lock file held while this tool runs
