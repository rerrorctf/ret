package commands

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"rctf/config"
)

func Ghidra(args []string) {
	if config.Verbose {
		fmt.Println("Ghidra:", args)
	}

	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
			fmt.Fprintf(os.Stderr, "usage: rctf ghidra\n")

			fmt.Fprintf(os.Stderr, "  🦖 ingests all added files then opens ghidra with rctf\n")

			fmt.Fprintf(os.Stderr, "\nsubcommands:\n")
			fmt.Fprintf(os.Stderr, "  ❓ help ~ print this message\n")

			fmt.Fprintf(os.Stderr, "\n~ 🚩 @rerrorctf 🚩 ~\n")
			fmt.Fprintf(os.Stderr, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

			os.Exit(0)
		}
	}

	if _, err := os.Stat(config.GhidraProjectPath); os.IsNotExist(err) {
		if config.Verbose {
			fmt.Println("mkdir", config.GhidraProjectPath)
		}
		err := os.MkdirAll(config.GhidraProjectPath, 0755)
		if err != nil {
			fmt.Println("error creating directory:", err)
			os.Exit(1)
		}
	}

	absoluteProjectPath, err := filepath.Abs(config.GhidraProjectPath + "/project.gpr")
	if err != nil {
		fmt.Println("error abs:", err)
		os.Exit(1)
	}

	fmt.Println("🦖 this might take a while...")

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
		config.GhidraInstallPath+"/ghidraRun", absoluteProjectPath)

	openGhidraOutput, err := openGhidra.CombinedOutput()
	if err != nil {
		fmt.Printf("%s\n", openGhidraOutput)
		fmt.Println("warning:\n", err)
	}
}
