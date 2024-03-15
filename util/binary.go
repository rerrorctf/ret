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

	jsonData, err := os.ReadFile(config.TaskName)
	if err != nil {
		return defaultBinaryName
	}

	var task data.Task

	err = json.Unmarshal(jsonData, &task)
	if err != nil {
		return defaultBinaryName
	}

	jsonData, err = os.ReadFile(config.RctfFilesName)
	if err != nil {
		return defaultBinaryName
	}

	var files data.Files

	err = json.Unmarshal(jsonData, &files)
	if err != nil {
		return defaultBinaryName
	}

	for _, file := range files.Files {
		if strings.Contains(file.Filename, "libc.so") {
			continue
		}
		return file.Filename
	}

	return defaultBinaryName
}
