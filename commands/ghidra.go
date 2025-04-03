package commands

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"ret/config"
	"ret/theme"
	"ret/util"
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
		},
		SeeAlso: []string{"add", "status", "ida", "pwn"}})
}

func GhidraHelp() string {
	return "adds files specified as arguments to this command, creates a ghidra project within the hidden .ret subdirectory, analyzes all added files then opens ghidra with ret\n\n" +
		"requires that " + theme.ColorPurple + "https://ghidra-sre.org/" + theme.ColorReset + " is installed\n\n" +
		"this command uses two configurable references to a typical ghidra installation both of which come from " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + "\n\n" +
		"1) " + theme.ColorYellow + "`\"ghidrarun\"`" + theme.ColorReset + " who's default value is " + theme.ColorGreen + "ghidra" + theme.ColorReset + "\n" +
		"bash should be able to use this name to find " + theme.ColorYellow + "ghidraRun" + theme.ColorReset + " on your path\n" +
		"this is typically located at " + theme.ColorBlue + "/opt/ghidra/ghidraRun" + theme.ColorReset + "\n\n" +
		"2) " + theme.ColorYellow + "`\"ghidraanalyzeheadless\"`" + theme.ColorReset + " who's default value is " + theme.ColorGreen + "ghidra-analyzeHeadless" + theme.ColorReset + "\n" +
		"bash should be able to use this name to find " + theme.ColorYellow + "analyzeHeadless" + theme.ColorReset + " on your path\n" +
		"this is typically located at " + theme.ColorBlue + "/opt/ghidra/support/analyzeHeadless" + theme.ColorReset + "\n"
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
	if _, err := os.Stat(config.FolderName + "/" + config.GhidraProject + "/ghidra.lock"); os.IsNotExist(err) {
		return false
	}

	return true
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
		fmt.Printf("😰"+theme.ColorYellow+" warning"+theme.ColorReset+": %s exists!\n", config.FolderName+"/"+config.GhidraProject+"/ghidra.lock")
		return
	}

	go ghidraSpinner()

	util.EnsureSkeleton()

	analyzeFile := exec.Command(
		config.GhidraAnalyzeHeadless,
		config.FolderName+"/"+config.GhidraProject,
		config.GhidraProject, "-recursive",
		"-import", config.FilesFolderName)

	analyzeFileOutput, err := analyzeFile.CombinedOutput()
	if err != nil {
		fmt.Printf("%s\n", analyzeFileOutput)
		fmt.Println("warning:\n", err)
	}

	openGhidra := exec.Command(config.GhidraRun, absoluteProjectPath)

	openGhidraOutput, err := openGhidra.CombinedOutput()
	if err != nil {
		fmt.Printf("%s\n", openGhidraOutput)
		fmt.Println("warning:\n", err)
	}

	fmt.Printf("\r")
}
