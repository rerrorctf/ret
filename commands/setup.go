package commands

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"ret/config"
	"ret/theme"
	"ret/util"
	"strings"
	"time"
)

func setupHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "setup" + theme.ColorReset + "\n")
	fmt.Printf("  🔧 setup ret\n")
	fmt.Printf("     " + theme.ColorGray + "asks questions to help you setup your ret config" + theme.ColorReset + "\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/ret.go" + theme.ColorReset + "\n")
}

func askQuestion(question string) {
	fmt.Printf("❓ "+theme.ColorReset+"%s"+theme.ColorReset+"\n", question)
}

func yesOrNo(question string) bool {
	fmt.Printf("❓ "+theme.ColorReset+"%s "+theme.ColorGray+"("+theme.ColorGreen+"Y"+theme.ColorGray+"/"+theme.ColorRed+"n"+theme.ColorGray+") "+theme.ColorReset, question)
	for {
		reader := bufio.NewReader(os.Stdin)
		backup, _, _ := reader.ReadRune()
		switch backup {
		case 'Y', 'y':
			return true
		case 'N', 'n':
			return false
		default:
			fmt.Print("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": expected either Y or n\n")
			continue
		}
	}
}

func readLine() string {
	reader := bufio.NewReader(os.Stdin)
	line, _, _ := reader.ReadLine()
	return strings.ReplaceAll(string(line), "\"", "")
}

func backupConfig() {
	configPath, err := config.GetConfigPath()
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	exists := util.FileExists(configPath)
	if exists {
		fmt.Printf("⚠️ "+theme.ColorGray+" \""+theme.ColorPurple+"%s"+theme.ColorGray+"\" "+theme.ColorYellow+"already exists"+theme.ColorReset+"!\n", configPath)
		if yesOrNo("would you like to make a backup?") {
			currentTime := time.Now().Format("20060102150405")
			backupConfigPath := fmt.Sprintf("%s_%s.bak", configPath, currentTime)
			fmt.Printf("copying \"%s\" to \"%s\"... ", configPath, backupConfigPath)
			util.CopyFile(configPath, backupConfigPath)
			fmt.Printf("done!\n")
		}
	}
}

func Setup(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			setupHelp()
			return
		}
	}

	backupConfig()

	// config.GhidraInstallPath
	fmt.Printf("🦖 ghidra install path: \"%s\"\n", config.GhidraInstallPath)

	if !yesOrNo(fmt.Sprintf("is ghidra is installed here \"%s\"?", config.GhidraInstallPath)) {
		for {
			askQuestion("where is ghidra installed? specifically what directory contains the file \"ghidraRun\"?")

			newGhidraInstallPath := readLine()

			if yesOrNo(fmt.Sprintf("is ghidra is installed here \"%s\"?", newGhidraInstallPath)) {
				config.GhidraInstallPath = newGhidraInstallPath
				break
			}
		}
	}

	// config.GhidraProjectPath
	fmt.Printf("🦖 ghidra project path : \"%s\"\n", config.GhidraProject)

	if yesOrNo("would you like to change the ghidra project name?") {
		for {
			askQuestion("what should the ghidra project be called?")

			newGhidraProjectPath := readLine()

			if yesOrNo(fmt.Sprintf("should the ghidra probject be called \"%s\"?", newGhidraProjectPath)) {
				config.GhidraProject = newGhidraProjectPath
				break
			}
		}
	}

	// config.IdaInstallPath
	fmt.Printf("💃 ida install path: \"%s\"\n", config.IdaInstallPath)

	if !yesOrNo(fmt.Sprintf("is ida is installed here \"%s\"?", config.IdaInstallPath)) {
		for {
			askQuestion("where is ida installed?")

			newIdaInstallPath := readLine()

			if yesOrNo(fmt.Sprintf("is ida is installed here \"%s\"?", newIdaInstallPath)) {
				config.IdaInstallPath = newIdaInstallPath
				break
			}
		}
	}

	fmt.Printf("💾 " + theme.ColorGray + "saving config... ")

	config.WriteUserConfig()

	fmt.Printf("done!\n")
}
