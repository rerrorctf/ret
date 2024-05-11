package util

import (
	"fmt"
	"os/exec"
	"ret/config"
	"ret/theme"
)

func grep2Win(path string) {
	grep2win := exec.Command("grep", "-aEoi", config.FlagFormat, path)
	grep2winOutput, err := grep2win.Output()
	if err == nil && len(grep2winOutput) > 0 {
		fmt.Printf(theme.ColorPurple+"[grep2win]"+theme.ColorReset+": %s", grep2winOutput)
	}
}

func ProcessFile(path string) {
	grep2Win(path)
}
