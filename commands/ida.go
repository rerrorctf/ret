package commands

import (
	"fmt"
	"os/exec"
	"ret/config"
	"time"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "ida",
		Emoji: "💃",
		Func:  Ida,
		Help:  IdaHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/ida.go",
		Arguments: []Argument{
			{
				Name:     "file",
				Optional: false,
				List:     true,
			},
		}})
}

func IdaHelp() string {
	return fmt.Sprintf("opens all added files then opens ida with ret\n")
}

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
		Add(args)
	}

	go idaSpinner()

	launchIda := exec.Command(config.IdaInstallPath + "/ida64")

	err := launchIda.Start()
	if err != nil {
		fmt.Println("warning:\n", err)
	}

	fmt.Printf("\r")
}
