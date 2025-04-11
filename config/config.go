package config

import (
	"encoding/json"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"ret/theme"
)

const (
	UserConfig           = ".config/ret"
	FolderName           = ".ret"
	FilesFolderName      = FolderName + "/files"
	RetFilesNames        = FilesFolderName + "/ret-files.json"
	DefaultBinaryName    = "task"
	NotesFileName        = FolderName + "/notes.json"
	CheckIfGhidraRunning = true
	TaskFileName         = FolderName + "/task.json"
)

var (
	GhidraRun             = "ghidra"
	GhidraAnalyzeHeadless = "ghidra-analyzeHeadless"
	GhidraProject         = "ghidra"
	IdaInstallPath        = "/opt/ida"
	PwnScriptName         = "go.py"
	PwnScriptTemplate     = ""
	FlagFileName          = FolderName + "/flag.json"
	FlagFormat            = "{.+}"
	WizardPreCommand      = ""
	WizardPostCommand     = ""
	Username              = ""
	ChatWebhookUrl        = ""
	ChatWebhookUrl2       = ""
	ChatWebhookUrl3       = ""
	GistToken             = ""
	ChefUrl               = "https://gchq.github.io/CyberChef/"
	CtfTimeUrls           = []string{}
)

type Config struct {
	GhidraRun             string   `json:"ghidrarun"`
	GhidraAnalyzeHeadless string   `json:"ghidraanalyzeheadless"`
	GhidraProject         string   `json:"ghidraproject"`
	IdaInstallPath        string   `json:"idainstallpath"`
	PwnScriptName         string   `json:"pwnscriptname"`
	PwnScriptTemplate     string   `json:"pwnscripttemplate"`
	Username              string   `json:"username"`
	ChatWebhookUrl        string   `json:"chatwebhookurl"`
	ChatWebhookUrl2       string   `json:"chatwebhookurl2"`
	ChatWebhookUrl3       string   `json:"chatwebhookurl3"`
	GistToken             string   `json:"gisttoken"`
	ChefUrl               string   `json:"chefurl"`
	CtfTimeUrls           []string `json:"ctftimeurls"`
}

func ParseUserConfig() {
	configPath := filepath.Join(os.Getenv("HOME"), UserConfig)

	jsonData, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	var userConfig Config

	err = json.Unmarshal(jsonData, &userConfig)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	if len(userConfig.GhidraRun) > 0 {
		GhidraRun = userConfig.GhidraRun
	}

	if len(userConfig.GhidraAnalyzeHeadless) > 0 {
		GhidraAnalyzeHeadless = userConfig.GhidraAnalyzeHeadless
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

	if len(userConfig.ChefUrl) > 0 {
		ChefUrl = userConfig.ChefUrl
	}

	if len(userConfig.CtfTimeUrls) > 0 {
		CtfTimeUrls = make([]string, len(userConfig.CtfTimeUrls))
		copy(CtfTimeUrls, userConfig.CtfTimeUrls)
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
	userConfig.GhidraRun = GhidraRun
	userConfig.GhidraAnalyzeHeadless = GhidraAnalyzeHeadless
	userConfig.GhidraProject = GhidraProject
	userConfig.IdaInstallPath = IdaInstallPath
	userConfig.PwnScriptName = PwnScriptName
	userConfig.PwnScriptTemplate = PwnScriptTemplate
	userConfig.Username = Username
	userConfig.ChatWebhookUrl = ChatWebhookUrl
	userConfig.ChatWebhookUrl2 = ChatWebhookUrl2
	userConfig.ChatWebhookUrl3 = ChatWebhookUrl3
	userConfig.GistToken = GistToken
	userConfig.ChefUrl = ChefUrl
	userConfig.CtfTimeUrls = make([]string, len(CtfTimeUrls))
	copy(userConfig.CtfTimeUrls, CtfTimeUrls)

	jsonData, err := json.MarshalIndent(userConfig, "", "  ")
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	err = os.WriteFile(configPath, jsonData, 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}
