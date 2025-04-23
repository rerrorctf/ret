package commands

import (
	"fmt"
	"ret/config"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "event",
		Emoji: "🗓️",
		Func:  Event,
		Help:  EventHelp,
		Arguments: []Argument{
			{
				Name:     "ctftime-url",
				Optional: true,
				List:     false,
			},
		},
		SeeAlso: []string{"name", "category", "description", "remote", "writeup"}})
}

func EventHelp() string {
	return "set or query a task's event with ret\n\n" +
		"supply no arguments to see the task's current event\n\n" +
		"note that task metadata is stored in hidden directory " + theme.ColorCyan + "`.ret`" + theme.ColorReset + " and therefore scoped to the cwd\n\n" +
		"task metadata is stored in the " + theme.ColorCyan + "`" + config.TaskFileName + "`" + theme.ColorReset + " file\n"
}

func displayCurrentTaskEvent() {
	event := util.GetCurrentTaskEvent()
	if len(event) == 0 {
		return
	}

	fmt.Printf("🗓️ "+theme.ColorBlue+"%s"+theme.ColorReset+"\n", event)
}

func setCurrentTaskEvent(newEvent string) {
	oldEvent := util.GetCurrentTaskEvent()

	if len(oldEvent) > 0 {
		fmt.Printf(theme.ColorGray+"🗓️ changing event from: "+theme.ColorRed+"%s"+theme.ColorGray+" to: "+theme.ColorGreen+"%s"+theme.ColorReset+"\n", oldEvent, newEvent)
	} else {
		fmt.Printf(theme.ColorGray+"🗓️ setting event to: "+theme.ColorGreen+"%s"+theme.ColorReset+"\n", newEvent)
	}

	util.SetCurrentTaskEvent(newEvent)
}

func Event(args []string) {
	if len(args) == 0 {
		displayCurrentTaskEvent()
		return
	}

	util.EnsureSkeleton()

	setCurrentTaskEvent(args[0])
}
