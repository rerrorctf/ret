package commands

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"ret/config"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "wizard",
		Emoji: "🧙",
		Func:  Wizard,
		Help:  WizardHelp,
		Arguments: []Argument{
			{
				Name:     "ip",
				Optional: true,
				List:     false,
				Default:  "127.0.0.1",
			},
			{
				Name:     "port",
				Optional: true,
				List:     false,
				Default:  "9001",
			},
		},
		SeeAlso: []string{"decompress", "add", "status", "pwn"}})
}

func WizardHelp() string {
	return "do " + theme.ColorPurple + "m" + theme.ColorBlue + "a" + theme.ColorGreen + "g" + theme.ColorYellow + "i" + theme.ColorRed + "c" + theme.ColorReset + " with ret\n\n" +
		"wizard is here to help! they simply run a few common commands suitable for a typical workflow\n\n" +
		"the workflow is quite well suited for typical rev and pwn tasks and may be useful for tasks in other categories too\n\n" +
		"sometimes " + theme.ColorRed + "the wizard makes mistakes" + theme.ColorReset + "! be sure to check its work by carefully reviewing the detailed output\n\n" +
		"steps the wizard performs:\n" +
		theme.ColorGray + "1) " + theme.ColorReset + "executes the " + theme.ColorYellow + "`\"wizardprecommand\"`" + theme.ColorReset + " string with " + theme.ColorGreen + "`\"bash -c\"`" + theme.ColorReset + " from " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + "\n" +
		theme.ColorGray + "2) " + theme.ColorReset + "searches for interesting files within the current directory. this is typically the task handout .zip file\n" +
		theme.ColorGray + "3) " + theme.ColorReset + "ensures that the hidden " + theme.ColorCyan + "`.ret`" + theme.ColorReset + " directory skeleton exists\n" +
		theme.ColorGray + "4) " + theme.ColorReset + "decompresses, using the " + theme.ColorGreen + "`decompress`" + theme.ColorReset + " command, any interesting files that it can\n" +
		theme.ColorGray + "5) " + theme.ColorReset + "adds any interesting files using the " + theme.ColorGreen + "`add`" + theme.ColorReset + " command. this includes those found by decompression and ignores the compressed archives themselves files\n" +
		theme.ColorGray + "6) " + theme.ColorReset + "shows the added files using the " + theme.ColorGreen + "`status`" + theme.ColorReset + " command\n" +
		theme.ColorGray + "7) " + theme.ColorReset + "invokes " + theme.ColorGreen + "`pwn`" + theme.ColorReset + " for you\n" +
		theme.ColorGray + "8) " + theme.ColorReset + "if you provided an `ip` or an `ip` and a `port` wizard will pass these to " + theme.ColorGreen + "`pwn`" + theme.ColorReset + " command\n" +
		theme.ColorGray + "9) " + theme.ColorReset + "executes the " + theme.ColorYellow + "`\"wizardpostcommand\"`" + theme.ColorReset + " string with " + theme.ColorGreen + "`\"bash -c\"`" + theme.ColorReset + " from " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + "\n" + theme.ColorReset
}

func runWizardCommand(command string) {
	if len(command) == 0 {
		return
	}

	fmt.Printf("🧙💬 " + theme.ColorGreen + "I see a custom incantation..." + theme.ColorReset + "\n")
	fmt.Printf("🧙📖 "+theme.ColorPurple+"%v"+theme.ColorReset+"\n", command)
	fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me run that for you!" + theme.ColorReset + "\n")

	magic := exec.Command("bash", "-c", command)

	magic.Stdin = os.Stdin
	magic.Stdout = os.Stdout
	magic.Stderr = os.Stderr

	err := magic.Run()
	if err != nil {
		log.Fatalln(err)
	}
}

func findInterestingFiles() []string {
	files, err := os.ReadDir(".")
	if err != nil {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": unable to read cwd!\n")
	}

	interestingFiles := []string{}

	for _, file := range files {
		if file.IsDir() {
			dirName := file.Name()

			if dirName[0] == '.' {
				continue
			}
			dirFiles, err := os.ReadDir("./" + dirName)
			if err != nil {
				log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": unable to read %s\n", dirName)
			}
			for _, dirfile := range dirFiles {
				fileName := dirfile.Name()

				if fileName[0] == '.' {
					continue
				}

				interestingFiles = append(interestingFiles, "./"+dirName+"/"+fileName)
			}
		} else {
			fileName := file.Name()

			if fileName[0] == '.' {
				continue
			}

			interestingFiles = append(interestingFiles, fileName)
		}

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

	fmt.Printf("🧙🪄 " + theme.ColorGreen + "Let me make a pwn template for you!" + theme.ColorReset + "\n")
	Pwn(args)

	runWizardCommand(config.WizardPostCommand)
}
