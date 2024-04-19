package config

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"rctf/data"
)

const (
	UserConfig      = ".config/rctf"
	FolderName      = ".rctf"
	FilesFolderName = FolderName + "/files"
	RctfFilesName   = FilesFolderName + "/rctf-files.json"
)

var (
	GhidraInstallPath = "/opt/ghidra"
	GhidraProjectPath = FolderName + "/ghidra"
	IdaInstallPath    = "/opt/ida"
	IdaProjectPath    = FolderName + "/ida"
	PwnScriptName     = "go.py"
	FlagFormat        = "flag{.+}"
)

func ParseUserConfig() {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	configPath := filepath.Join(currentUser.HomeDir, UserConfig)

	jsonData, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	var userConfig data.Config

	err = json.Unmarshal(jsonData, &userConfig)
	if err != nil {
		fmt.Println("error unmarshalling json:", err)
		os.Exit(1)
	}

	if len(userConfig.GhidraInstallPath) > 0 {
		GhidraInstallPath = userConfig.GhidraInstallPath
	}

	if len(userConfig.GhidraProjectPath) > 0 {
		GhidraProjectPath = userConfig.GhidraProjectPath
	}

	if len(userConfig.IdaInstallPath) > 0 {
		IdaInstallPath = userConfig.IdaInstallPath
	}

	if len(userConfig.IdaProjectPath) > 0 {
		IdaProjectPath = userConfig.IdaProjectPath
	}

	if len(userConfig.PwnScriptName) > 0 {
		PwnScriptName = userConfig.PwnScriptName
	}

	if len(userConfig.FlagFormat) > 0 {
		FlagFormat = userConfig.FlagFormat
	}
}

func WriteUserConfig() {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	configPath := filepath.Join(currentUser.HomeDir, UserConfig)

	var userConfig data.Config
	userConfig.GhidraInstallPath = GhidraInstallPath
	userConfig.GhidraProjectPath = GhidraProjectPath
	userConfig.IdaInstallPath = IdaInstallPath
	userConfig.IdaProjectPath = IdaProjectPath
	userConfig.PwnScriptName = PwnScriptName
	userConfig.FlagFormat = FlagFormat

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
