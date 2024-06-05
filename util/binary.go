package util

import (
	"encoding/json"
	"os"
	"ret/config"
	"ret/data"
	"strings"
)

func GuessBinary() []string {
	binaries := make([]string, 0)

	jsonData, err := os.ReadFile(config.RetFilesNames)
	if err != nil {
		binaries = append(binaries, config.DefaultBinaryName)
		return binaries
	}

	var files data.Files

	err = json.Unmarshal(jsonData, &files)
	if err != nil {
		binaries = append(binaries, config.DefaultBinaryName)
		return binaries
	}

	for _, file := range files.Files {

		if file.FileType != data.FILE_TYPE_ELF {
			continue
		}
		if strings.Contains(file.Filename, ".so") {
			continue
		}

		binaries = append(binaries, file.Filename)
	}

	if len(binaries) > 0 {
		return binaries
	}

	binaries = append(binaries, config.DefaultBinaryName)
	return binaries
}

func BinaryIsExecutable(file string) bool {
	stat, err := os.Stat(file)
	if err != nil {
		return false
	}

	return stat.Mode().Perm()&0100 != 0
}
