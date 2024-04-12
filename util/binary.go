package util

import (
	"encoding/json"
	"os"
	"rctf/config"
	"rctf/data"
	"strings"
)

func GuessBinary() string {
	defaultBinaryName := "task"

	jsonData, err := os.ReadFile(config.RctfFilesName)
	if err != nil {
		return defaultBinaryName
	}

	var files data.Files

	err = json.Unmarshal(jsonData, &files)
	if err != nil {
		return defaultBinaryName
	}

	for _, file := range files.Files {
		if strings.Contains(file.Filename, ".so") {
			continue
		}

		if strings.Contains(file.Type, "ELF") {
			return file.Filename
		}
	}

	return defaultBinaryName
}
