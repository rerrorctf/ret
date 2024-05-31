package util

import (
	"encoding/json"
	"fmt"
	"os"
	"ret/config"
	"ret/data"
	"ret/theme"
)

func GetCurrentFlag() (error, string) {
	jsonData, err := os.ReadFile(config.FlagFileName)
	if err != nil {
		return err, ""
	}

	var flag data.Flag

	err = json.Unmarshal(jsonData, &flag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		return err, ""
	}

	return nil, flag.Flag
}
