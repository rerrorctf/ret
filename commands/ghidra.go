package commands

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"ret/config"
	"ret/theme"
	"ret/util"
	"strings"
	"time"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "ghidra",
		Emoji: "🦖",
		Func:  Ghidra,
		Help:  GhidraHelp,
		Arguments: []Argument{
			{
				Name:     "file",
				Optional: true,
				List:     true,
			},
		}})
}

func GhidraHelp() string {
	return "ingests all added files then opens ghidra with ret\n"
}

func ghidraSpinner() {
	emojis := []string{
		"🍎", "🥑", "🥓", "🥖", "🍌", "🥯", "🫐", "🍔", "🥦", "🥩",
		"🥕", "🥂", "🍫", "🍪", "🥒", "🧀", "🥚", "🍳", "🍟", "🍇",
		"🍏", "🍔", "🍯", "🥝", "🍋", "🥬", "🍞", "🥗", "🍣", "🍜",
		"🥟", "🍲", "🌭", "🍕", "🍝", "🌮", "🍉", "🍊", "🍓", "🚩",
	}

	for {
		for _, e := range emojis {
			fmt.Printf("\r%s -> 🦖", e)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func ghidraAlreadyRunning() bool {
	pidofCmd := exec.Command("pidof", "java")
	pidofCmd.Stdin = nil
	var pidofOutput bytes.Buffer
	pidofCmd.Stdout = &pidofOutput
	if err := pidofCmd.Run(); err != nil {
		return false
	}

	scanner := bufio.NewScanner(&pidofOutput)
	for scanner.Scan() {
		javaPid := scanner.Text()

		cmdline, err := os.ReadFile("/proc/" + javaPid + "/cmdline")
		if err != nil {
			continue
		}

		if strings.Contains(string(cmdline), "ghidra") {
			return true
		}
	}

	return false
}

func Ghidra(args []string) {
	if _, err := os.Stat(config.FolderName + "/" + config.GhidraProject); os.IsNotExist(err) {
		err := os.MkdirAll(config.FolderName+"/"+config.GhidraProject, 0755)
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
		}
	}

	absoluteProjectPath, err := filepath.Abs(config.FolderName + "/" + config.GhidraProject + "/" + config.GhidraProject + ".gpr")
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	if len(args) > 0 {
		Add(args)
	}

	if config.CheckIfGhidraRunning && ghidraAlreadyRunning() {
		fmt.Println("😰" + theme.ColorYellow + " warning" + theme.ColorReset + ": ghidra already seems to be running")
		return
	}

	go ghidraSpinner()

	util.EnsureSkeleton()

	analyzeFile := exec.Command(
		config.GhidraInstallPath+"/support/analyzeHeadless",
		config.FolderName+"/"+config.GhidraProject,
		config.GhidraProject, "-recursive",
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

	fmt.Printf("\r")
}
