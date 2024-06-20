package commands

import (
	"fmt"
	"log"
	"ret/theme"
	"ret/util"
)

func syscallHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "syscall" + theme.ColorReset + " [(x86/32)/(x64/64)]" + theme.ColorReset + " [regex-pattern]\n")
	fmt.Printf("  📞 check syscalls by regex with ret\n")

	fmt.Printf(theme.ColorBlue + "\n  uses" + theme.ColorGray + ": \n")
	fmt.Printf(theme.ColorGreen + "    x86" + theme.ColorGray + ": /usr/include/x86_64-linux-gnu/asm/unistd_32.h" + theme.ColorReset + "\n")
	fmt.Printf(theme.ColorGreen + "    x64" + theme.ColorGray + ": /usr/include/x86_64-linux-gnu/asm/unistd_64.h" + theme.ColorReset + "\n")

	fmt.Printf(theme.ColorBlue + "\n  examples" + theme.ColorGray + ": \n")
	fmt.Printf(theme.ColorPurple + "    syscall x64 \" 0\"" + theme.ColorReset + "\n")
	fmt.Printf(theme.ColorPurple + "    syscall x64 write" + theme.ColorReset + "\n")
	fmt.Printf(theme.ColorPurple + "    syscall 32 read" + theme.ColorReset + "\n")
	fmt.Printf(theme.ColorPurple + "    syscall x86 10[0-9]" + theme.ColorReset + "\n\n")

	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/syscall.go" + theme.ColorReset + "\n")
}

func Syscall(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			syscallHelp()
			return
		}
	}

	arch := "x64"
	pattern := "."

	if len(args) > 1 {
		arch = args[0]
		pattern = args[1]
	} else if len(args) > 0 {
		arch = args[0]
	}

	switch arch {
	case "x86":
		{
			util.Grep("/usr/include/x86_64-linux-gnu/asm/unistd_32.h", pattern)
		}
	case "32":
		{
			util.Grep("/usr/include/x86_64-linux-gnu/asm/unistd_32.h", pattern)
		}
	case "x64":
		{
			util.Grep("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", pattern)
		}
	case "64":
		{
			util.Grep("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", pattern)
		}
	default:
		{
			syscallHelp()
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": invalid arch btw \"%v\"\n", args[0])
		}
	}
}
