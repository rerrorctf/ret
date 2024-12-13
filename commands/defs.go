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

func printStdFileNos() {
	printColoredDefTitle("STDIN_FILENO")
	printColoredDef("unistd.h", "STDIN_FILENO", "0")

	printColoredDefTitle("STDOUT_FILENO")
	printColoredDef("unistd.h", "STDOUT_FILENO", "1")

	printColoredDefTitle("STDERR_FILENO")
	printColoredDef("unistd.h", "STDERR_FILENO", "2")

	fmt.Println()
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

	fmt.Println()
}

func Defs(args []string) {
	// STDIN_FILENO / STDOUT_FILENO / STDERR_FILENO
	printStdFileNos()

	// SEEK_SET / SEEK_CUR / SEEK_END
	printSeeks()
}
