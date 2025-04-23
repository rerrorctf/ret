package commands

import (
	"fmt"
	"ret/config"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "category",
		Emoji: "😼",
		Func:  Category,
		Help:  CategoryHelp,
		Arguments: []Argument{
			{
				Name:     "task-category",
				Optional: true,
				List:     false,
			},
		},
		SeeAlso: []string{"name", "description", "event", "remote", "writeup"}})
}

func CategoryHelp() string {
	return "set or query a task's category with ret\n\n" +
		"supply no arguments to see the current category\n\n" +
		"note that task metadata is stored in hidden directory " + theme.ColorCyan + "`.ret`" + theme.ColorReset + " and therefore scoped to the cwd\n\n" +
		"task metadata is stored in the " + theme.ColorCyan + "`" + config.TaskFileName + "`" + theme.ColorReset + " file\n"
}

func displayCurrentTaskCategory() {
	category := util.GetCurrentTaskCategory()
	if len(category) == 0 {
		return
	}

	fmt.Printf("😼 "+theme.ColorBlue+"%s"+theme.ColorReset+"\n", category)
}

func setCurrentTaskCategory(newCategory string) {
	oldCategory := util.GetCurrentTaskCategory()

	if len(oldCategory) > 0 {
		fmt.Printf(theme.ColorGray+"😼 changing category from: "+theme.ColorRed+"%s"+theme.ColorGray+" to: "+theme.ColorGreen+"%s"+theme.ColorReset+"\n", oldCategory, newCategory)
	} else {
		fmt.Printf(theme.ColorGray+"😼 setting category to: "+theme.ColorGreen+"%s"+theme.ColorReset+"\n", newCategory)
	}

	util.SetCurrentTaskCategory(newCategory)
}

func Category(args []string) {
	if len(args) == 0 {
		displayCurrentTaskCategory()
		return
	}

	util.EnsureSkeleton()

	setCurrentTaskCategory(args[0])
}
