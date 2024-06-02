package commands

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"ret/config"
	"ret/theme"
	"ret/util"
	"strings"
)

func runWizardCommand(command string) {
	if len(command) == 0 {
		return
	}

	fmt.Printf("🧙💬 " + theme.ColorGreen + "I see a custom incantation..." + theme.ColorReset + "\n")
	fmt.Printf("🧙📖 "+theme.ColorPurple+"%v"+theme.ColorReset+"\n", command)
	fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me run that for you!" + theme.ColorReset + "\n")

	magic := exec.Command("bash", "-c", command)

	out, err := magic.CombinedOutput()
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Print(string(out))
}

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
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"wizard"+theme.ColorGray+" [ip] [port]"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  🧙 do "+theme.ColorPurple+"m"+theme.ColorBlue+"a"+theme.ColorGreen+"g"+theme.ColorYellow+"i"+theme.ColorRed+"c"+theme.ColorReset+" with ret\n")
			fmt.Fprintf(os.Stderr, "  🔗 "+theme.ColorGray+"https://github.com/rerrorctf/ret/blob/main/commands/wizard.go"+theme.ColorReset+"\n")
			os.Exit(0)
		}
	}

	runWizardCommand(config.WizardPreCommand)

	// create interesting files list
	interestingFiles := findInterestingFiles()

	// ensure skeleton
	_, err := os.Stat(config.FolderName)
	if os.IsNotExist(err) {
		fmt.Printf("🧙💬 "+theme.ColorGreen+"I see that you don't have a "+theme.ColorCyan+"\"%s\""+theme.ColorGreen+" directory."+theme.ColorReset+"\n", config.FolderName)
		fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me create that for you!" + theme.ColorReset + "\n")
		util.EnsureSkeleton()
	}

	unzippedAny := false

	// unzip
	fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me try to decompress those interesting files for you!" + theme.ColorReset + "\n")
	for _, file := range interestingFiles {
		decompessed := util.DecompressFile(file)
		if decompessed {
			fmt.Printf("🧙💬 "+theme.ColorGreen+"I decompressed "+theme.ColorCyan+"\"%s\""+theme.ColorGreen+" for you."+theme.ColorReset+"\n", file)
			unzippedAny = true
		}
	}

	if unzippedAny {
		interestingFiles = findInterestingFiles()
	}

	// current flag format reminder
	fmt.Printf("🧙💬 "+theme.ColorGreen+"The current flag format is "+theme.ColorPurple+"%s\n"+theme.ColorReset, config.FlagFormat)

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
		if _, decompressable := util.IsDecompressable(file); decompressable {
			fmt.Printf("🧙🪄 "+theme.ColorGreen+"Skipping "+theme.ColorCyan+"\"%s\""+theme.ColorGreen+" as it was decompressed."+theme.ColorReset+"\n", file)
			continue
		}

		filesToAdd = append(filesToAdd, file)
	}

	if len(filesToAdd) > 0 {
		Add(filesToAdd)
	}

	// show status
	fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me show the status!" + theme.ColorReset + "\n")
	Status([]string{})

	// if there are one or more elf binaries then pwn
	for _, file := range filesToAdd {
		if strings.Contains(file, ".so") {
			continue
		}

		result := util.RunFileCommandOnFile(file)

		if strings.Contains(result, "ELF") {
			fmt.Printf("🧙💬 " + theme.ColorGreen + "I see that there is at least one ELF." + theme.ColorReset + "\n")
			fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me make a pwn template for you!" + theme.ColorReset + "\n")
			Pwn(args)
			break
		}
	}

	runWizardCommand(config.WizardPostCommand)
}
