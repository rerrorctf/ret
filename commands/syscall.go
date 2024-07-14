package commands

import (
	"fmt"
	"log"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "syscall",
		Emoji: "📞",
		Func:  Syscall,
		Help:  SyscallHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/status.go",
		Arguments: []Argument{
			{
				Name:     "(x86/32)/(x64/64)",
				Optional: true,
				List:     false,
			},
			{
				Name:     "regex",
				Optional: true,
				List:     false,
			},
		}})
}

func SyscallHelp() string {
	return fmt.Sprintf("check syscalls by regex with ret\n") +

		fmt.Sprintf(theme.ColorBlue+"\n  uses"+theme.ColorGray+": \n") +
		fmt.Sprintf(theme.ColorGreen+"    x86"+theme.ColorGray+": /usr/include/x86_64-linux-gnu/asm/unistd_32.h"+theme.ColorReset+"\n") +
		fmt.Sprintf(theme.ColorGreen+"    x64"+theme.ColorGray+": /usr/include/x86_64-linux-gnu/asm/unistd_64.h"+theme.ColorReset+"\n") +

		fmt.Sprintf(theme.ColorBlue+"\n  examples"+theme.ColorGray+": \n") +
		fmt.Sprintf(theme.ColorPurple+"    syscall x64 \" 0\""+theme.ColorReset+"\n") +
		fmt.Sprintf(theme.ColorPurple+"    syscall x64 write"+theme.ColorReset+"\n") +
		fmt.Sprintf(theme.ColorPurple+"    syscall 32 read"+theme.ColorReset+"\n") +
		fmt.Sprintf(theme.ColorPurple+"    syscall x86 10[0-9]"+theme.ColorReset+"\n\n")
}

func Syscall(args []string) {
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
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": invalid arch btw \"%v\"\n", args[0])
		}
	}
}
