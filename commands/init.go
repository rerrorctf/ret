package commands

import (
	"fmt"
	"log"
	"ret/config"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:      "init",
		Emoji:     "🚀",
		Func:      Init,
		Help:      InitHelp,
		Arguments: nil,
		SeeAlso:   []string{"event", "name", "category", "writeup"}})
}

func InitHelp() string {
	return "init a task with ret\n"
}

func handleEvent() {
	if len(config.CtfTimeUrls) == 1 {
		util.SetCurrentTaskEvent(config.CtfTimeUrls[0])
		return
	}

	if len(config.CtfTimeUrls) < 2 {
		return
	}

	fmt.Println("🚀 " + theme.ColorPurple + "which event does this task belong to?" + theme.ColorReset)

	for idx, ctfTimeUrl := range config.CtfTimeUrls {
		fmt.Printf(theme.ColorGray+"["+theme.ColorReset+"%d"+theme.ColorGray+"]"+theme.ColorGreen+" %s"+theme.ColorReset+"\n", idx, ctfTimeUrl)
	}

	fmt.Printf("🚀 "+theme.ColorPurple+"enter the corresponding number from "+theme.ColorReset+"0 "+theme.ColorPurple+"to "+theme.ColorReset+"%d: "+theme.ColorReset, len(config.CtfTimeUrls)-1)

	eventIdx := -1
	fmt.Scanf("%d", &eventIdx)

	if (eventIdx < 0) || (eventIdx >= len(config.CtfTimeUrls)) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %d is not a valid choice\n", eventIdx)
	}

	util.SetCurrentTaskEvent(config.CtfTimeUrls[eventIdx])

	Event(nil)
}

func handleName() {
	fmt.Println("🚀 " + theme.ColorPurple + "what is the name of this task?" + theme.ColorReset)

	var name string
	fmt.Scanf("%s", &name)

	util.SetCurrentTaskName(name)

	Name(nil)
}

func handleCategory() {
	fmt.Println("🚀 " + theme.ColorPurple + "to which category does this task belong?" + theme.ColorReset)

	var category string
	fmt.Scanf("%s", &category)

	util.SetCurrentTaskCategory(category)

	Category(nil)
}

func Init(args []string) {
	util.EnsureSkeleton()

	handleEvent()
	handleName()
	handleCategory()
}
