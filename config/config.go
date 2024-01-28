package config

const (
	UserConfig      = ".config/rctf"
	FolderName      = ".rctf"
	TaskName        = FolderName + "/task.json"
	FilesFolderName = FolderName + "/files"
	RctfFilesName   = FilesFolderName + "/rctf-files.json"
)

var (
	GhidraInstallPath = "/opt/ghidra/"
	GhidraProjectPath = FolderName + "/ghidra"
	PwnScriptName     = "go.py"
	Verbose           = false
)
