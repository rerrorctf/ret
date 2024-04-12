package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"rctf/config"
	"rctf/data"
	"rctf/theme"
)

func writeUserConfig() {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	configPath := filepath.Join(currentUser.HomeDir, config.UserConfig)

	var userConfig data.Config
	userConfig.GhidraInstallPath = config.GhidraInstallPath
	userConfig.GhidraProjectPath = config.GhidraProjectPath
	userConfig.IdaInstallPath = config.IdaInstallPath
	userConfig.IdaProjectPath = config.IdaProjectPath
	userConfig.PwnScriptName = config.PwnScriptName
	userConfig.FlagFormat = config.FlagFormat

	jsonData, err := json.MarshalIndent(userConfig, "", "  ")
	if err != nil {
		fmt.Println("error marshalling json:", err)
		os.Exit(1)
	}

	err = os.WriteFile(configPath, jsonData, 0644)
	if err != nil {
		fmt.Println("error writing to file:", err)
		os.Exit(1)
	}
}

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

	writeUserConfig()

	fmt.Printf("new flag format: %v\n", config.FlagFormat)
}
