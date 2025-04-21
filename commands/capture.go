package commands

import (
	"fmt"
	"ret/config"
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
		SeeAlso: []string{"writeup"}})
}

func CaptureHelp() string {
	return "set or query a task's flag with ret\n\n" +
		"supply no arguments to see the current flag\n\n" +
		"note that task metadata is stored in hidden directory " + theme.ColorCyan + "`.ret`" + theme.ColorReset + " and therefore scoped to the cwd\n\n" +
		"task metadata is stored in the " + theme.ColorCyan + "`" + config.TaskFileName + "`" + theme.ColorReset + " file\n"
}

func displayCurrentTaskFlag() {
	flag := util.GetCurrentTaskFlag()
	if len(flag) == 0 {
		return
	}

	fmt.Printf("🏁 "+theme.ColorPurple+"%s"+theme.ColorReset+"\n", flag)
}

func setCurrentTaskFlag(newFlag string) {
	oldFlag := util.GetCurrentTaskFlag()

	if len(oldFlag) > 0 {
		fmt.Printf(theme.ColorGray+"🏁 changing flag from: "+theme.ColorRed+"%s"+theme.ColorGray+" to: "+theme.ColorGreen+"%s"+theme.ColorReset+"\n", oldFlag, newFlag)
	} else {
		fmt.Printf(theme.ColorGray+"🏁 setting flag to: "+theme.ColorGreen+"%s"+theme.ColorReset+"\n", newFlag)
	}

	util.SetCurrentTaskFlag(newFlag)
}

func Capture(args []string) {
	if len(args) == 0 {
		displayCurrentTaskFlag()
		return
	}

	util.EnsureSkeleton()

	setCurrentTaskFlag(args[0])
}
