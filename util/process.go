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

func grep2Win(file *data.File, path string, log *os.File) {
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
	if err == nil {
		fmt.Printf(theme.ColorPurple+"[grep2win]"+theme.ColorReset+": %s", grep2winOutput)
		fmt.Fprintf(log, "[grep2win]: %s", grep2winOutput)
	}
}

func checksec(file *data.File, path string, log *os.File) {
	checksec := exec.Command("pwn", "checksec", path)
	checksecOutput, err := checksec.CombinedOutput()
	if err == nil {
		fmt.Printf(theme.ColorPurple+"[checksec]"+theme.ColorReset+": %s", checksecOutput)
		fmt.Fprintf(log, "[checksec]: %s", checksecOutput)
	}
}

func ProcessFile(file *data.File, path string) {
	logFilePath := config.FilesFolderName + "/" + file.SHA256 + "/rctflog.txt"
	logFile, err := os.Create(logFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: unable to open process log %v\n", logFilePath)
		return
	}
	defer logFile.Close()

	grep2Win(file, path, logFile)
	checksec(file, path, logFile)
}
