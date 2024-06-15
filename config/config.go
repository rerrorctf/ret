package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"ret/data"
	"ret/theme"
)

const (
	UserConfig        = ".config/ret"
	FolderName        = ".ret"
	FilesFolderName   = FolderName + "/files"
	RetFilesNames     = FilesFolderName + "/ret-files.json"
	DefaultBinaryName = "task"
)

var (
	GhidraInstallPath  = "/opt/ghidra"
	GhidraProjectPath  = FolderName + "/ghidra"
	IdaInstallPath     = "/opt/ida"
	IdaProjectPath     = FolderName + "/ida"
	PwnScriptName      = "go.py"
	PwnScriptTemplate  = ""
	FlagFileName       = FolderName + "/flag.json"
	FlagFormat         = "flag{.+}"
	WizardPreCommand   = ""
	WizardPostCommand  = ""
	Username           = ""
	ChatWebhookUrl     = ""
	GistToken          = ""
	OpenAIKey          = ""
	GoogleCloudProject = "default"
	GoogleCloudRegion  = "europe-west3-c"
	GoogleCloudSSHKey  = ""
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
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
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

	if len(userConfig.PwnScriptTemplate) > 0 {
		PwnScriptTemplate = userConfig.PwnScriptTemplate
	}

	if len(userConfig.FlagFormat) > 0 {
		FlagFormat = userConfig.FlagFormat
	}

	if len(userConfig.WizardPreCommand) > 0 {
		WizardPreCommand = userConfig.WizardPreCommand
	}

	if len(userConfig.WizardPostCommand) > 0 {
		WizardPostCommand = userConfig.WizardPostCommand
	}

	if len(userConfig.Username) > 0 {
		Username = userConfig.Username
	}

	if len(userConfig.ChatWebhookUrl) > 0 {
		ChatWebhookUrl = userConfig.ChatWebhookUrl
	}

	if len(userConfig.GistToken) > 0 {
		GistToken = userConfig.GistToken
	}

	if len(userConfig.OpenAIKey) > 0 {
		OpenAIKey = userConfig.OpenAIKey
	}

	if len(userConfig.GoogleCloudProject) > 0 {
		GoogleCloudProject = userConfig.GoogleCloudProject
	}

	if len(userConfig.GoogleCloudRegion) > 0 {
		GoogleCloudRegion = userConfig.GoogleCloudRegion
	}

	if len(userConfig.GoogleCloudSSHKey) > 0 {
		GoogleCloudSSHKey = userConfig.GoogleCloudSSHKey
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
	userConfig.PwnScriptTemplate = PwnScriptTemplate
	userConfig.FlagFormat = FlagFormat
	userConfig.WizardPreCommand = WizardPreCommand
	userConfig.WizardPostCommand = WizardPostCommand
	userConfig.Username = Username
	userConfig.ChatWebhookUrl = ChatWebhookUrl
	userConfig.GistToken = GistToken
	userConfig.OpenAIKey = OpenAIKey
	userConfig.GoogleCloudProject = GoogleCloudProject
	userConfig.GoogleCloudRegion = GoogleCloudRegion
	userConfig.GoogleCloudSSHKey = GoogleCloudSSHKey

	jsonData, err := json.MarshalIndent(userConfig, "", "  ")
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	err = os.WriteFile(configPath, jsonData, 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}
