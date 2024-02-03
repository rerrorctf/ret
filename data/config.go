package data

type Config struct {
	GhidraInstallPath string `json:"ghidrainstallpath"`
	GhidraProjectPath string `json:"ghidraprojectpath"`
	PwnScriptName     string `json:"pwnscriptname"`
	MonitorWebhook    string `json:"monitorwebhook"`
}
