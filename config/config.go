package config

const (
	FolderName        = ".rctf"
	TaskName          = FolderName + "/task.json"
	FilesFolderName   = FolderName + "/files"
	RctfFilesName     = FilesFolderName + "/rctf-files.json"
	GhidraInstallPath = "/opt/ghidra_11.0_PUBLIC/"
)

var (
	Verbose = false
)
