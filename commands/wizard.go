package commands

import (
	"fmt"
	"log"
	"os"
	"rctf/config"
	"rctf/theme"
	"rctf/util"
	"strings"
)

func findInterestingFiles() []string {
	files, err := os.ReadDir(".")
	if err != nil {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": unable read cwd!\n")
	}

	interestingFiles := []string{}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		fileName := file.Name()

		if fileName[0] == '.' {
			continue
		}

		interestingFiles = append(interestingFiles, fileName)
	}

	if len(interestingFiles) < 1 {
		fmt.Printf("🧙💬 " + theme.ColorGreen + "I don't see any interesting files here..." + theme.ColorReset + "\n")
		return interestingFiles
	}

	if len(interestingFiles) > 1 {
		fmt.Printf("🧙💬 "+theme.ColorGreen+"I see %d interesting files here..."+theme.ColorReset+"\n", len(interestingFiles))
	} else {
		fmt.Printf("🧙💬 " + theme.ColorGreen + "I see an interesting file here..." + theme.ColorReset + "\n")
	}

	for _, file := range interestingFiles {
		fmt.Printf(" 👀 "+theme.ColorCyan+"%s\n"+theme.ColorReset, file)
	}

	return interestingFiles
}

func Wizard(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"wizard"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  🧙 do "+theme.ColorPurple+"magic"+theme.ColorReset+" with rctf\n")
			os.Exit(0)
		}
	}

	// create interesting files list
	interestingFiles := findInterestingFiles()

	// ensure skeleton
	_, err := os.Stat(config.FolderName)
	if os.IsNotExist(err) {
		fmt.Printf("🧙💬 "+theme.ColorGreen+"I see that you don't have a %s.. let me create that for you!"+theme.ColorReset+" 🪄\n", config.FolderName)
		util.EnsureSkeleton()
	}

	// init task
	_, err = os.Stat(config.TaskName)
	if os.IsNotExist(err) {
		fmt.Printf("🧙💬 "+theme.ColorGreen+"I see that you don't have a %s.. let me create that for you!"+theme.ColorReset+" 🪄\n", config.TaskName)
		Init([]string{"flag{.+}"})
	}

	unzippedAny := false

	// unzip
	for _, file := range interestingFiles {
		result := util.RunFileCommandOnFile(file)

		if strings.Contains(result, "Zip archive data") {
			fmt.Printf("🧙💬 "+theme.ColorGreen+"I see that %s is a zip file.. let me unzip that for you!"+theme.ColorReset+" 🪄\n", file)

			util.UnzipFile(file)

			unzippedAny = true
		}
	}

	if unzippedAny {
		interestingFiles = findInterestingFiles()
	}

	// add files
	if len(interestingFiles) > 1 {
		fmt.Printf("🧙💬 " + theme.ColorGreen + "Let me add those interesting files for you!" + theme.ColorReset + " 🪄\n")
	} else {
		fmt.Printf("🧙💬 " + theme.ColorGreen + "Let me add that interesting file for you!" + theme.ColorReset + " 🪄\n")
	}

	Add(interestingFiles)

	// show status
	Status([]string{})

	// if binary then pwn
	for _, file := range interestingFiles {
		result := util.RunFileCommandOnFile(file)

		if strings.Contains(result, "ELF") {
			fmt.Printf("🧙💬 "+theme.ColorGreen+"I see that %s is an ELF.. let me pwn that for you!"+theme.ColorReset+" 🪄\n", file)

			Pwn([]string{})
			break
		}
	}
}
