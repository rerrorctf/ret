package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"ret/config"
	"ret/data"
	"ret/theme"
	"ret/util"
)

func displayCurrentFlag() {
	flag, err := util.GetCurrentFlag()
	if err != nil {
		fmt.Fprintf(os.Stderr, "⚠️ "+theme.ColorYellow+" warning"+theme.ColorReset+": flag file \"%s\" doesn't exist\n", config.FlagFileName)
		return
	}

	fmt.Printf("🚩 "+theme.ColorPurple+"%s"+theme.ColorPurple+"\n", flag)
}

func scoreNewFlag(newFlag string) {
	var flag data.Flag

	flag.Flag = newFlag

	jsonData, err := json.MarshalIndent(flag, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	err = os.WriteFile(config.FlagFileName, jsonData, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🚩 "+theme.ColorPurple+"%s"+theme.ColorPurple+"\n", flag)
}

func CtfHelp() {
	fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"ctf"+theme.ColorGray+" [flag]"+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, "  🚩 capture the flag with ret\n")
	fmt.Fprintf(os.Stderr, "  🔗 "+theme.ColorGray+"https://github.com/rerrorctf/ret/blob/main/commands/ctf.go"+theme.ColorReset+"\n")
	os.Exit(0)
}

func Ctf(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			CtfHelp()
		}
	} else {
		displayCurrentFlag()
		return
	}

	scoreNewFlag(args[0])
}
