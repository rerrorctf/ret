package commands

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"ret/config"
	"ret/data"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "capture",
		Emoji: "🏁",
		Func:  Capture,
		Help:  CaptureHelp,
		Arguments: []Argument{
			{
				Name:     "flag",
				Optional: true,
				List:     false,
			},
		},
		SeeAlso: []string{"format", "writeup"}})
}

func CaptureHelp() string {
	return "capture the flag with ret\n\n" +
		"supply no arguments to see the currently captured flag\n\n" +
		"note that captured flags are stored in hidden directory " + theme.ColorCyan + "`.ret`" + theme.ColorReset + " and therefore scoped to the cwd\n\n" +
		"flags are stored in the " + theme.ColorCyan + "`.ret/flag.json`" + theme.ColorReset + " file\n"
}

func displayCurrentFlag() {
	flag, err := util.GetCurrentFlag()
	if err != nil {
		fmt.Printf("⚠️ "+theme.ColorYellow+" warning"+theme.ColorReset+": flag file \"%s\" doesn't exist\n", config.FlagFileName)
		return
	}

	fmt.Printf("🏁 "+theme.ColorPurple+"%s"+theme.ColorReset+"\n", flag)
}

func scoreNewFlag(newFlag string) {
	var flag data.Flag

	flag.Flag = newFlag

	jsonData, err := json.MarshalIndent(flag, "", "  ")
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	err = os.WriteFile(config.FlagFileName, jsonData, 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	fmt.Printf("🏁 "+theme.ColorPurple+"%s"+theme.ColorReset+"\n", flag.Flag)
}

func Capture(args []string) {
	if len(args) == 0 {
		displayCurrentFlag()
		return
	}

	util.EnsureSkeleton()

	scoreNewFlag(args[0])
}
