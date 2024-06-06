package data

type Config struct {
	GhidraInstallPath string `json:"ghidrainstallpath"`
	GhidraProjectPath string `json:"ghidraprojectpath"`
	IdaInstallPath    string `json:"idainstallpath"`
	IdaProjectPath    string `json:"idaprojectpath"`
	PwnScriptName     string `json:"pwnscriptname"`
	PwnScriptTemplate string `json:"pwnscripttemplate"`
	FlagFormat        string `json:"flagformat"`
	WizardPreCommand  string `json:"wizardprecommand"`
	WizardPostCommand string `json:"wizardpostcommand"`
	ChatUsername      string `json:"chatusername"`
	ChatWebhookUrl    string `json:"chatwebhookurl"`
	GistToken         string `json:"gisttoken"`
	OpenAIKey         string `json:"openaikey"`
}
