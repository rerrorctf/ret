package util

import (
	"encoding/json"
	"os"
	"ret/config"
	"ret/data"
)

func GetCurrentFlag() (string, error) {
	jsonData, err := os.ReadFile(config.FlagFileName)
	if err != nil {
		return "", err
	}

	var flag data.Flag

	err = json.Unmarshal(jsonData, &flag)
	if err != nil {
		return "", err
	}

	return flag.Flag, nil
}
