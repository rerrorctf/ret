package data

type Config struct {
	GhidraInstallPath string `json:"ghidrainstallpath"`
	GhidraProjectPath string `json:"ghidraprojectpath"`
	IdaInstallPath    string `json:"idainstallpath"`
	IdaProjectPath    string `json:"idaprojectpath"`
	PwnScriptName     string `json:"pwnscriptname"`
	FlagFormat        string `json:"flagformat"`
	WizardPreCommand  string `json:"wizardprecommand"`
	WizardPostCommand string `json:"wizardpostcommand"`
}
