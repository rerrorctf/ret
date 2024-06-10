package util

import (
	"encoding/json"
	"fmt"
	"os"
	"ret/config"
	"ret/data"
	"ret/theme"
)

func GetCurrentFlag() (string, error) {
	jsonData, err := os.ReadFile(config.FlagFileName)
	if err != nil {
		return "", err
	}

	var flag data.Flag

	err = json.Unmarshal(jsonData, &flag)
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		return "", err
	}

	return flag.Flag, nil
}
