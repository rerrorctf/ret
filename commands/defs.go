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

func printColoredDefTitle(def string, include string) {
	if len(include) > 0 {
		fmt.Printf(theme.ColorGreen + def + theme.ColorGray + " #include <" + include + ">\n" + theme.ColorReset)
	} else {
		fmt.Printf(theme.ColorGreen + def + "\n" + theme.ColorReset)
	}
}

func printColoredDef(path string, def string, val string) {
	if len(path) > 0 {
		fmt.Printf(theme.ColorGray + "  " + path + " ~ " + theme.ColorReset)
	}
	fmt.Printf(theme.ColorPurple + "#define " + theme.ColorBlue + def + " " + theme.ColorReset + val + "\n")
}

func printStdFileNos() {
	printColoredDefTitle("STDIN_FILENO", "unistd.h")
	printColoredDef("", "STDIN_FILENO", "0")

	printColoredDefTitle("STDOUT_FILENO", "unistd.h")
	printColoredDef("", "STDOUT_FILENO", "1")

	printColoredDefTitle("STDERR_FILENO", "unistd.h")
	printColoredDef("", "STDERR_FILENO", "2")

	fmt.Println()
}

func printSeeks() {
	printColoredDefTitle("SEEK_SET", "stdio.h")
	printColoredDef("/usr/include/linux/fs.h", "SEEK_SET", "0")
	printColoredDef("/usr/include/stdio.h", "SEEK_SET", "0")

	printColoredDefTitle("SEEK_CUR", "stdio.h")
	printColoredDef("/usr/include/linux/fs.h", "SEEK_CUR", "1")
	printColoredDef("/usr/include/stdio.h", "SEEK_CUR", "1")

	printColoredDefTitle("SEEK_END", "stdio.h")
	printColoredDef("/usr/include/linux/fs.h", "SEEK_END", "2")
	printColoredDef("/usr/include/stdio.h", "SEEK_END", "2")

	fmt.Println()
}

func printMem() {
	printColoredDefTitle("PROT_READ", "sys/mman.h")
	printColoredDef("/usr/include/asm-generic/mman-common.h", "PROT_READ", "1")
	printColoredDef("/usr/include/x86_64-linux-gnu/bits/mman-linux.h", "PROT_READ", "1")

	printColoredDefTitle("PROT_WRITE", "sys/mman.h")
	printColoredDef("/usr/include/asm-generic/mman-common.h", "PROT_WRITE", "2")
	printColoredDef("/usr/include/x86_64-linux-gnu/bits/mman-linux.h", "PROT_WRITE", "2")

	printColoredDefTitle("PROT_EXEC", "sys/mman.h")
	printColoredDef("/usr/include/asm-generic/mman-common.h", "PROT_EXEC", "4")
	printColoredDef("/usr/include/x86_64-linux-gnu/bits/mman-linux.h", "PROT_EXEC", "4")

	printColoredDefTitle("MAP_SHARED", "sys/mman.h")
	printColoredDef("/usr/include/linux/mman.h", "MAP_SHARED", "1")
	printColoredDef("/usr/include/x86_64-linux-gnu/bits/mman-linux.h", "MAP_SHARED", "1")

	printColoredDefTitle("MAP_PRIVATE", "sys/mman.h")
	printColoredDef("/usr/include/linux/mman.h", "MAP_PRIVATE", "2")
	printColoredDef("/usr/include/x86_64-linux-gnu/bits/mman-linux.h", "MAP_PRIVATE", "2")

	printColoredDefTitle("MAP_SHARED_VALIDATE", "sys/mman.h")
	printColoredDef("/usr/include/linux/mman.h", "MAP_SHARED_VALIDATE", "3")
	printColoredDef("/usr/include/x86_64-linux-gnu/bits/mman-linux.h", "MAP_SHARED_VALIDATE", "3")

	printColoredDefTitle("MAP_FIXED", "sys/mman.h")
	printColoredDef("/usr/include/asm-generic/mman-common.h", "MAP_FIXED", "16")
	printColoredDef("/usr/include/x86_64-linux-gnu/bits/mman-linux.h", "MAP_FIXED", "16")

	printColoredDefTitle("MAP_ANONYMOUS", "sys/mman.h")
	printColoredDef("/usr/include/asm-generic/mman-common.h", "MAP_ANONYMOUS", "32")
}

func Defs(args []string) {
	// STDIN_FILENO / STDOUT_FILENO / STDERR_FILENO
	printStdFileNos()

	// SEEK_SET / SEEK_CUR / SEEK_END
	printSeeks()

	// PROT_READ / PROT_WRITE / PROT_EXEC /
	// MAP_SHARED / MAP_PRIVATE / MAP_SHARED_VALIDATE / MAP_FIXED / MAP_ANONYMOUS
	printMem()
}
