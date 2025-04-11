package commands

import (
	"fmt"
	"ret/config"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "name",
		Emoji: "🏷️",
		Func:  Name,
		Help:  NameHelp,
		Arguments: []Argument{
			{
				Name:     "task-name",
				Optional: true,
				List:     false,
			},
		},
		SeeAlso: nil})
}

func NameHelp() string {
	return "set or query a task's name with ret\n\n" +
		"supply no arguments to see the current name\n\n" +
		"note that task metadata is stored in hidden directory " + theme.ColorCyan + "`.ret`" + theme.ColorReset + " and therefore scoped to the cwd\n\n" +
		"task metadata is stored in the " + theme.ColorCyan + "`" + config.TaskFileName + "`" + theme.ColorReset + " file\n"
}

func displayCurrentTaskName() {
	name := util.GetCurrentTaskName()
	if len(name) == 0 {
		return
	}

	fmt.Printf("🏷️ "+theme.ColorBlue+"%s"+theme.ColorReset+"\n", name)
}

func setCurrentTaskName(newName string) {
	oldName := util.GetCurrentTaskName()

	if len(oldName) > 0 {
		fmt.Printf(theme.ColorGray+"🏷️ changing name from: "+theme.ColorRed+"%s"+theme.ColorGray+" to: "+theme.ColorGreen+"%s"+theme.ColorReset+"\n", oldName, newName)
	} else {
		fmt.Printf(theme.ColorGray+"🏷️ setting name to: "+theme.ColorGreen+"%s"+theme.ColorReset+"\n", newName)
	}

	util.SetCurrentTaskName(newName)
}

func Name(args []string) {
	if len(args) == 0 {
		displayCurrentTaskName()
		return
	}

	util.EnsureSkeleton()

	setCurrentTaskName(args[0])
}
