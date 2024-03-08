package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"rctf/config"
	"rctf/data"
	"rctf/theme"
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
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"ida"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  💃 opens all added files then opens ida with rctf\n")
			os.Exit(0)
		}
	}

	go idaSpinner()

	jsonData, err := os.ReadFile(config.TaskName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var task data.Task

	err = json.Unmarshal(jsonData, &task)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	jsonData, err = os.ReadFile(config.RctfFilesName)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var files data.Files

	err = json.Unmarshal(jsonData, &files)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	idaArgs := make([]string, 0)

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
