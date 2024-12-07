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

func Defs(args []string) {
	fmt.Printf(theme.ColorGreen + "SEEK_SET\n" + theme.ColorReset)

	fmt.Printf(theme.ColorGray + "  /usr/include/linux/fs.h ~ " + theme.ColorReset)
	fmt.Printf(theme.ColorPurple + "#define " + theme.ColorBlue + "SEEK_SET " + theme.ColorReset + "0\n")

	fmt.Printf(theme.ColorGray + "  /usr/include/stdio.h ~ " + theme.ColorReset)
	fmt.Printf(theme.ColorPurple + "#define " + theme.ColorBlue + "SEEK_SET " + theme.ColorReset + "0\n")

	fmt.Printf(theme.ColorGreen + "SEEK_CUR\n" + theme.ColorReset)

	fmt.Printf(theme.ColorGray + "  /usr/include/linux/fs.h ~ " + theme.ColorReset)
	fmt.Printf(theme.ColorPurple + "#define " + theme.ColorBlue + "SEEK_CUR " + theme.ColorReset + "1\n")

	fmt.Printf(theme.ColorGray + "  /usr/include/stdio.h ~ " + theme.ColorReset)
	fmt.Printf(theme.ColorPurple + "#define " + theme.ColorBlue + "SEEK_CUR " + theme.ColorReset + "1\n")

	fmt.Printf(theme.ColorGreen + "SEEK_END\n" + theme.ColorReset)

	fmt.Printf(theme.ColorGray + "  /usr/include/linux/fs.h ~ " + theme.ColorReset)
	fmt.Printf(theme.ColorPurple + "#define " + theme.ColorBlue + "SEEK_END " + theme.ColorReset + "2\n")

	fmt.Printf(theme.ColorGray + "  /usr/include/stdio.h ~ " + theme.ColorReset)
	fmt.Printf(theme.ColorPurple + "#define " + theme.ColorBlue + "SEEK_END " + theme.ColorReset + "2\n")
}
