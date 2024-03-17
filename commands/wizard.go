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
		fmt.Printf("🧙💬 "+theme.ColorGreen+"I see "+theme.ColorPurple+"%d"+theme.ColorGreen+" interesting files here!"+theme.ColorReset+"\n", len(interestingFiles))
	} else {
		fmt.Printf("🧙💬 " + theme.ColorGreen + "I see an interesting file here!" + theme.ColorReset + "\n")
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
			fmt.Fprintf(os.Stderr, "  🧙 do "+theme.ColorPurple+"m"+theme.ColorBlue+"a"+theme.ColorGreen+"g"+theme.ColorYellow+"i"+theme.ColorRed+"c"+theme.ColorReset+" with rctf\n")
			os.Exit(0)
		}
	}

	// create interesting files list
	interestingFiles := findInterestingFiles()

	// ensure skeleton
	_, err := os.Stat(config.FolderName)
	if os.IsNotExist(err) {
		fmt.Printf("🧙💬 "+theme.ColorGreen+"I see that you don't have a "+theme.ColorCyan+"\"%s\""+theme.ColorGreen+" directory."+theme.ColorReset+"\n", config.FolderName)
		fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me create that for you!" + theme.ColorReset + "\n")
		util.EnsureSkeleton()
	}

	// init task
	_, err = os.Stat(config.TaskName)
	if os.IsNotExist(err) {
		fmt.Printf("🧙💬 "+theme.ColorGreen+"I see that you don't have a "+theme.ColorCyan+"\"%s\""+theme.ColorGreen+" file."+theme.ColorReset+"\n", config.TaskName)
		fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me create that for you!" + theme.ColorReset + "\n")
		Init([]string{"flag{.+}"})
	}

	unzippedAny := false

	// unzip
	for _, file := range interestingFiles {
		result := util.RunFileCommandOnFile(file)

		if strings.Contains(result, "Zip archive data") {
			fmt.Printf("🧙💬 "+theme.ColorGreen+"I see that "+theme.ColorCyan+"\"%s\""+theme.ColorGreen+" is a zip file."+theme.ColorReset+"\n", file)
			fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me unzip that for you!" + theme.ColorReset + "\n")

			util.UnzipFile(file)

			unzippedAny = true
		}
	}

	if unzippedAny {
		interestingFiles = findInterestingFiles()
	}

	// add files
	if len(interestingFiles) > 0 {
		if len(interestingFiles) > 1 {
			fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me add those interesting files for you!" + theme.ColorReset + "\n")
		} else {
			fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me add that interesting file for you!" + theme.ColorReset + "\n")
		}
	}

	filesToAdd := []string{}

	for _, file := range interestingFiles {
		result := util.RunFileCommandOnFile(file)

		if strings.Contains(result, "Zip archive data") {
			fmt.Printf("🧙💬 "+theme.ColorGreen+"Skipping "+theme.ColorCyan+"\"%s\""+theme.ColorGreen+" as it is a zip file."+theme.ColorReset+"\n", file)
			continue
		}

		filesToAdd = append(filesToAdd, file)
	}

	Add(filesToAdd)

	// show status
	fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me show the status!" + theme.ColorReset + "\n")
	Status([]string{})

	// if there is a single elf binary then pwn
	numElfFiles := 0
	elfFileIndex := -1

	for i, file := range filesToAdd {
		if strings.Contains(file, ".so") {
			continue
		}

		result := util.RunFileCommandOnFile(file)

		if strings.Contains(result, "ELF") {
			numElfFiles += 1
			elfFileIndex = i
		}
	}

	if numElfFiles == 1 {
		solitaryElfName := filesToAdd[elfFileIndex]
		fmt.Printf("🧙💬 "+theme.ColorGreen+"I see that "+theme.ColorCyan+"\"%s\""+theme.ColorGreen+" is an ELF."+theme.ColorReset+"\n", solitaryElfName)
		fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me pwn that for you!" + theme.ColorReset + "\n")
		Pwn([]string{})
	}
}
