package commands

import (
	"fmt"
	"os"
	"os/exec"
	"rctf/config"
)

func GhidraHelp() {
	fmt.Println("rctf ghidra help would go here...")
}

func Ghidra(args []string) {
	if config.Verbose {
		fmt.Println("Ghidra:", args)
	}

	if len(args) > 0 {
		switch args[0] {
		case "help":
			GhidraHelp()
			os.Exit(0)
		}
	}

	analyzeFile := exec.Command(
		config.GhidraInstallPath+"/support/analyzeHeadless",
		config.GhidraProjectPath,
		"project",
		"-import", config.FilesFolderName)

	analyzeFileOutput, err := analyzeFile.CombinedOutput()
	if err != nil {
		fmt.Printf("%s\n", analyzeFileOutput)
		fmt.Println("warning:\n", err)
	}

	openGhidra := exec.Command(
		config.GhidraInstallPath+"/ghidraRun",
		"/home/user/rctf/ghidra/project.gpr")

	openGhidraOutput, err := openGhidra.CombinedOutput()
	if err != nil {
		fmt.Printf("%s\n", openGhidraOutput)
		fmt.Println("warning:\n", err)
	}
}
