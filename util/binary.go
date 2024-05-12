package util

import (
	"encoding/json"
	"os"
	"ret/config"
	"ret/data"
	"strings"
)

func GuessBinary() string {

	jsonData, err := os.ReadFile(config.RetFilesNames)
	if err != nil {
		return config.DefaultBinaryName
	}

	var files data.Files

	err = json.Unmarshal(jsonData, &files)
	if err != nil {
		return config.DefaultBinaryName
	}

	for _, file := range files.Files {
		if strings.Contains(file.Filename, ".so") {
			continue
		}

		if strings.Contains(file.Type, "ELF") {
			return file.Filename
		}
	}

	return config.DefaultBinaryName
}

func BinaryIsExecutable(file string) bool {
	stat, err := os.Stat(file)
	if err != nil {
		return false
	}

	return stat.Mode().Perm()&0100 != 0
}
