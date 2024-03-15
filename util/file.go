package util

import (
	"fmt"
	"os/exec"
)

func RunFileCommandOnFile(path string) string {
	fileOutput := exec.Command("file", path)

	fileOutputResult, err := fileOutput.Output()
	if err != nil {
		fmt.Printf("warning: unable to get output from file on %s\n", path)
		return ""
	}

	return string(fileOutputResult[len(path)+2 : len(fileOutputResult)-1])
}

func UnzipFile(path string) {
	fileOutput := exec.Command("unzip", path)

	fileOutputResult, err := fileOutput.Output()
	if err != nil {
		fmt.Printf("warning: unable to unzip file %s\n", path)
		return
	}

	fmt.Printf("%s", fileOutputResult)
}
