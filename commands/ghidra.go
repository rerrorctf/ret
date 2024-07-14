package commands

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"ret/config"
	"ret/theme"
	"time"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "ghidra",
		Emoji: "🦖",
		Func:  Ghidra,
		Help:  GhidraHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/ghidra.go",
		Arguments: []Argument{
			{
				Name:     "file",
				Optional: true,
				List:     true,
			},
		}})
}

func GhidraHelp() string {
	return fmt.Sprintf("ingests all added files then opens ghidra with ret\n")
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

	go ghidraSpinner()

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
