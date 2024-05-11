package util

import (
	"encoding/json"
	"os"
	"rctf/config"
	"rctf/data"
	"strings"
)

const (
	DefaultBinaryName = "task"
)

func GuessBinary() string {

	jsonData, err := os.ReadFile(config.RctfFilesName)
	if err != nil {
		return DefaultBinaryName
	}

	var files data.Files

	err = json.Unmarshal(jsonData, &files)
	if err != nil {
		return DefaultBinaryName
	}

	for _, file := range files.Files {
		if strings.Contains(file.Filename, ".so") {
			continue
		}

		if strings.Contains(file.Type, "ELF") {
			return file.Filename
		}
	}

	return DefaultBinaryName
}

func BinaryIsExecutable(file string) bool {
	stat, err := os.Stat(file)
	if err != nil {
		return false
	}

	return stat.Mode().Perm()&0100 != 0
}
