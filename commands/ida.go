package commands

import (
	"fmt"
	"os"
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
			fmt.Fprintf(os.Stderr, "  💃 ingests all added files then opens ida with rctf\n")
			os.Exit(0)
		}
	}

	// TODO
	go idaSpinner()
}
