package commands

import (
	"fmt"
	"ret/config"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "description",
		Emoji: "🗣️", // a rose by any other name would smell as 1337
		Func:  Description,
		Help:  DescriptionHelp,
		Arguments: []Argument{
			{
				Name:     "task-description",
				Optional: true,
				List:     false,
			},
		},
		SeeAlso: []string{"name", "category", "event", "remote", "writeup"}})
}

func DescriptionHelp() string {
	return "set or query a task's description with ret\n\n" +
		"supply no arguments to see the current description\n\n" +
		"note that task metadata is stored in hidden directory " + theme.ColorCyan + "`.ret`" + theme.ColorReset + " and therefore scoped to the cwd\n\n" +
		"task metadata is stored in the " + theme.ColorCyan + "`" + config.TaskFileName + "`" + theme.ColorReset + " file\n"
}

func displayCurrentTaskDescription() {
	description := util.GetCurrentTaskDescription()
	if len(description) == 0 {
		return
	}

	fmt.Printf("🗣️ "+theme.ColorBlue+"%s"+theme.ColorReset+"\n", description)
}

func setCurrentTaskDescription(newDescription string) {
	oldDescription := util.GetCurrentTaskDescription()

	if len(oldDescription) > 0 {
		fmt.Printf(theme.ColorGray+"🗣️ changing description from: "+theme.ColorRed+"%s"+theme.ColorGray+" to: "+theme.ColorGreen+"%s"+theme.ColorReset+"\n", oldDescription, newDescription)
	} else {
		fmt.Printf(theme.ColorGray+"🗣️ setting description to: "+theme.ColorGreen+"%s"+theme.ColorReset+"\n", newDescription)
	}

	util.SetCurrentTaskDescription(newDescription)
}

func Description(args []string) {
	if len(args) == 0 {
		displayCurrentTaskDescription()
		return
	}

	util.EnsureSkeleton()

	setCurrentTaskDescription(args[0])
}
