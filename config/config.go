package config

const (
	UserConfig      = ".config/rctf"
	FolderName      = ".rctf"
	TaskName        = FolderName + "/rctf-task.json"
	FilesFolderName = FolderName + "/files"
	RctfFilesName   = FilesFolderName + "/rctf-files.json"
)

var (
	GhidraInstallPath = "/opt/ghidra"
	GhidraProjectPath = FolderName + "/ghidra"
	IdaInstallPath    = "/opt/ida"
	IdaProjectPath    = FolderName + "/ida"
	PwnScriptName     = "go.py"
	Verbose           = false
	FlagFormat        = "flag{.+}"
)
