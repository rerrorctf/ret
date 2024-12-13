package commands

import (
	"fmt"
	"ret/theme"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "defs",
		Emoji: "🙉",
		Func:  Defs,
		Help:  DefsHelp,
	})
}

func DefsHelp() string {
	return ""
}

func printColoredDefTitle(def string) {
	fmt.Printf(theme.ColorGreen + def + "\n" + theme.ColorReset)
}

func printColoredDef(path string, def string, val string) {
	fmt.Printf(theme.ColorGray + "  " + path + " ~ " + theme.ColorReset)
	fmt.Printf(theme.ColorPurple + "#define " + theme.ColorBlue + def + " " + theme.ColorReset + val + "\n")
}

func printSeeks() {
	printColoredDefTitle("SEEK_SET")
	printColoredDef("/usr/include/linux/fs.h", "SEEK_SET", "0")
	printColoredDef("/usr/include/stdio.h", "SEEK_SET", "0")

	printColoredDefTitle("SEEK_CUR")
	printColoredDef("/usr/include/linux/fs.h", "SEEK_CUR", "1")
	printColoredDef("/usr/include/stdio.h", "SEEK_CUR", "1")

	printColoredDefTitle("SEEK_END")
	printColoredDef("/usr/include/linux/fs.h", "SEEK_END", "2")
	printColoredDef("/usr/include/stdio.h", "SEEK_END", "2")
}

func Defs(args []string) {
	// SEEK_SET / SEEK_CUR / SEEK_END
	printSeeks()
}
