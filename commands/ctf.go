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
		Name:  "ctf",
		Emoji: "🚩",
		Func:  Ctf,
		Help:  CtfHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/ctf.go",
		Arguments: []Argument{
			{
				Name:     "flag",
				Optional: true,
				List:     false,
			},
		}})
}

func CtfHelp() {
	fmt.Printf("  🚩 capture the flag with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/ctf.go" + theme.ColorReset + "\n")
}

func displayCurrentFlag() {
	flag, err := util.GetCurrentFlag()
	if err != nil {
		fmt.Printf("⚠️ "+theme.ColorYellow+" warning"+theme.ColorReset+": flag file \"%s\" doesn't exist\n", config.FlagFileName)
		return
	}

	fmt.Printf("🚩 "+theme.ColorPurple+"%s"+theme.ColorReset+"\n", flag)
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

	fmt.Printf("🚩 "+theme.ColorPurple+"%s"+theme.ColorReset+"\n", flag.Flag)
}

func Ctf(args []string) {
	if len(args) == 0 {
		displayCurrentFlag()
		return
	}

	util.EnsureSkeleton()

	scoreNewFlag(args[0])
}
