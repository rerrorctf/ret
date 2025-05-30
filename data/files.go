package data

const (
	FILE_TYPE_ELF     string = "elf"
	FILE_TYPE_MACHO   string = "mach-o"
	FILE_TYPE_UNKNOWN string = "unknown"
)

var FileMagics = map[string][]byte{
	FILE_TYPE_ELF:   {0x7F, 0x45, 0x4C, 0x46},
	FILE_TYPE_MACHO: {0xCA, 0xFE, 0xBA, 0xBE},
}

type File struct {
	Filename string `json:"filename"`
	Filepath string `json:"filepath"`
	Size     int    `json:"size"`
	FileType string `json:"filetype"`
	SHA256   string `json:"sha256"`
}

type Files struct {
	Files []File `json:"files"`
}
