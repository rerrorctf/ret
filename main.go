package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"rctf/commands"
	"rctf/config"
	"rctf/data"
)

func help() {
	fmt.Println("Usage: rctf [init/add/status]...")
}

func createDefaultConfig(configPath string) {
	var userConfig data.Config

	userConfig.GhidraInstallPath = config.GhidraInstallPath
	userConfig.GhidraProjectPath = config.GhidraProjectPath
	userConfig.PwnScriptName = config.PwnScriptName

	jsonData, err := json.MarshalIndent(userConfig, "", "  ")
	if err != nil {
		fmt.Println("error marshalling json:", err)
		os.Exit(1)
	}

	err = os.WriteFile(configPath, jsonData, 0644)
	if err != nil {
		fmt.Println("error opening file:", err)
		os.Exit(1)
	}
}

func parseUserConfig() {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	configPath := filepath.Join(currentUser.HomeDir, config.UserConfig)

	jsonData, err := os.ReadFile(configPath)
	if err != nil {
		createDefaultConfig(configPath)
		return
	}

	var userConfig data.Config

	err = json.Unmarshal(jsonData, &userConfig)
	if err != nil {
		fmt.Println("error unmarshalling json:", err)
		os.Exit(1)
	}

	if len(userConfig.GhidraInstallPath) > 0 {
		config.GhidraInstallPath = userConfig.GhidraInstallPath

		if config.Verbose {
			fmt.Printf("config: %v\n", userConfig.GhidraInstallPath)
		}
	}

	if len(userConfig.GhidraProjectPath) > 0 {
		config.GhidraProjectPath = userConfig.GhidraProjectPath

		if config.Verbose {
			fmt.Printf("config: %v\n", userConfig.GhidraProjectPath)
		}
	}

	if len(userConfig.PwnScriptName) > 0 {
		config.PwnScriptName = userConfig.PwnScriptName

		if config.Verbose {
			fmt.Printf("config: %v\n", userConfig.PwnScriptName)
		}
	}
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

	parseUserConfig()

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
