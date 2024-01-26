package commands

import (
	"fmt"
	"os"
	"rctf/config"
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
	if config.Verbose {
		fmt.Println("Ida:", args)
	}

	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, "usage: rctf ida\n")
			fmt.Fprintf(os.Stderr, "  💃 ingests all added files then opens ida with rctf\n")
			os.Exit(0)
		}
	}

	// TODO
	go idaSpinner()
}
