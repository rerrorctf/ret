package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"ret/config"
	"ret/data"
	"ret/theme"
	"time"
)

func idaSpinner() {
	emojis := []string{
		"🍎", "🥑", "🥓", "🥖", "🍌", "🥯", "🫐", "🍔", "🥦", "🥩",
		"🥕", "🥂", "🍫", "🍪", "🥒", "🧀", "🥚", "🍳", "🍟", "🍇",
		"🍏", "🍔", "🍯", "🥝", "🍋", "🥬", "🍞", "🥗", "🍣", "🍜",
		"🥟", "🍲", "🌭", "🍕", "🍝", "🌮", "🍉", "🍊", "🍓", "🚩",
	}

	for {
		for _, e := range emojis {
			fmt.Printf("\r%s -> 💃", e)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func Ida(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"ida"+theme.ColorGray+" [file file...]"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  💃 opens all added files then opens ida with ret\n")
			fmt.Fprintf(os.Stderr, "  🔗 "+theme.ColorGray+"https://github.com/rerrorctf/ret/blob/main/commands/ida.go"+theme.ColorReset+"\n")
			os.Exit(0)
		}
	}

	if len(args) > 0 {
		Add(args)
	}

	go idaSpinner()

	idaArgs := make([]string, 0)

	jsonData, err := os.ReadFile(config.RetFilesNames)
	if err == nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var files data.Files

	err = json.Unmarshal(jsonData, &files)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, file := range files.Files {
		idaArgs = append(idaArgs, file.Filepath)
	}

	launchIda := exec.Command(config.IdaInstallPath+"/ida64", idaArgs...)

	err = launchIda.Start()
	if err != nil {
		fmt.Println("warning:\n", err)
	}

	fmt.Printf("\r")
}
