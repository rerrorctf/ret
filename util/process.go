package util

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"rctf/config"
	"rctf/data"
	"rctf/theme"
)

func grep2Win(path string) {
	jsonData, err := os.ReadFile(config.TaskName)
	if err != nil {
		fmt.Println("error reading:", err)
		os.Exit(1)
	}

	var task data.Task

	err = json.Unmarshal(jsonData, &task)
	if err != nil {
		fmt.Println("error unmarshalling json:", err)
		os.Exit(1)
	}

	grep2win := exec.Command("grep", "-aEoi", task.FlagFormat, path)
	grep2winOutput, err := grep2win.Output()
	if err == nil && len(grep2winOutput) > 0 {
		fmt.Printf(theme.ColorPurple+"[grep2win]"+theme.ColorReset+": %s", grep2winOutput)
	}
}

func ProcessFile(path string) {
	grep2Win(path)
}
