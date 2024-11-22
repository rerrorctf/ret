package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"ret/theme"
)

const (
	UserConfig        = ".config/ret"
	FolderName        = ".ret"
	FilesFolderName   = FolderName + "/files"
	RetFilesNames     = FilesFolderName + "/ret-files.json"
	DefaultBinaryName = "task"
	NotesFileName     = FolderName + "/notes.json"
)

var (
	GhidraInstallPath  = "/opt/ghidra"
	GhidraProject      = "ghidra"
	IdaInstallPath     = "/opt/ida"
	PwnScriptName      = "go.py"
	PwnScriptTemplate  = ""
	FlagFileName       = FolderName + "/flag.json"
	FlagFormat         = "{.+}"
	Username           = ""
	ChatWebhookUrl     = ""
	ChatWebhookUrl2    = ""
	ChatWebhookUrl3    = ""
	GistToken          = ""
	GoogleCloudProject = "default"
	GoogleCloudRegion  = "europe-west3-c"
	GoogleCloudSSHKey  = ""
	ChefUrl            = "https://gchq.github.io/CyberChef/"
	CtfTimeUrl         = ""
)

type Config struct {
	GhidraInstallPath  string `json:"ghidrainstallpath"`
	GhidraProject      string `json:"ghidraproject"`
	IdaInstallPath     string `json:"idainstallpath"`
	PwnScriptName      string `json:"pwnscriptname"`
	PwnScriptTemplate  string `json:"pwnscripttemplate"`
	Username           string `json:"username"`
	ChatWebhookUrl     string `json:"chatwebhookurl"`
	ChatWebhookUrl2    string `json:"chatwebhookurl2"`
	ChatWebhookUrl3    string `json:"chatwebhookurl3"`
	GistToken          string `json:"gisttoken"`
	GoogleCloudProject string `json:"googlecloudproject"`
	GoogleCloudRegion  string `json:"googlecloudregion"`
	GoogleCloudSSHKey  string `json:"googlecloudsshkey"`
	ChefUrl            string `json:"chefurl"`
	CtfTimeUrl         string `json:"ctftimeurl"`
}

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

	var userConfig Config

	err = json.Unmarshal(jsonData, &userConfig)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	if len(userConfig.GhidraInstallPath) > 0 {
		GhidraInstallPath = userConfig.GhidraInstallPath
	}

	if len(userConfig.GhidraProject) > 0 {
		GhidraProject = userConfig.GhidraProject
	}

	if len(userConfig.IdaInstallPath) > 0 {
		IdaInstallPath = userConfig.IdaInstallPath
	}

	if len(userConfig.PwnScriptName) > 0 {
		PwnScriptName = userConfig.PwnScriptName
	}

	if len(userConfig.PwnScriptTemplate) > 0 {
		PwnScriptTemplate = userConfig.PwnScriptTemplate
	}

	if len(userConfig.Username) > 0 {
		Username = userConfig.Username
	}

	if len(userConfig.ChatWebhookUrl) > 0 {
		ChatWebhookUrl = userConfig.ChatWebhookUrl
	}

	if len(userConfig.ChatWebhookUrl2) > 0 {
		ChatWebhookUrl2 = userConfig.ChatWebhookUrl2
	}

	if len(userConfig.ChatWebhookUrl3) > 0 {
		ChatWebhookUrl3 = userConfig.ChatWebhookUrl3
	}

	if len(userConfig.GistToken) > 0 {
		GistToken = userConfig.GistToken
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

	if len(userConfig.ChefUrl) > 0 {
		ChefUrl = userConfig.ChefUrl
	}

	if len(userConfig.CtfTimeUrl) > 0 {
		CtfTimeUrl = userConfig.CtfTimeUrl
	}
}

func GetConfigPath() (string, error) {
	currentUser, err := user.Current()
	if err != nil {
		return "", err
	}

	configPath := filepath.Join(currentUser.HomeDir, UserConfig)
	return configPath, nil
}

func WriteUserConfig() {
	configPath, err := GetConfigPath()
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
		return
	}

	var userConfig Config
	userConfig.GhidraInstallPath = GhidraInstallPath
	userConfig.GhidraProject = GhidraProject
	userConfig.IdaInstallPath = IdaInstallPath
	userConfig.PwnScriptName = PwnScriptName
	userConfig.PwnScriptTemplate = PwnScriptTemplate
	userConfig.Username = Username
	userConfig.ChatWebhookUrl = ChatWebhookUrl
	userConfig.ChatWebhookUrl2 = ChatWebhookUrl2
	userConfig.ChatWebhookUrl3 = ChatWebhookUrl3
	userConfig.GistToken = GistToken
	userConfig.GoogleCloudProject = GoogleCloudProject
	userConfig.GoogleCloudRegion = GoogleCloudRegion
	userConfig.GoogleCloudSSHKey = GoogleCloudSSHKey
	userConfig.ChefUrl = ChefUrl
	userConfig.CtfTimeUrl = CtfTimeUrl

	jsonData, err := json.MarshalIndent(userConfig, "", "  ")
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	err = os.WriteFile(configPath, jsonData, 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}
