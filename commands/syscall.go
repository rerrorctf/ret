package commands

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"ret/theme"
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

func grep(path string, pattern string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": opening file %v\n", path)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if match, _ := regexp.MatchString(pattern, line); match {
			fmt.Println(line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
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
			grep("/usr/include/x86_64-linux-gnu/asm/unistd_32.h", pattern)
		}
	case "32":
		{
			grep("/usr/include/x86_64-linux-gnu/asm/unistd_32.h", pattern)
		}
	case "x64":
		{
			grep("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", pattern)
		}
	case "64":
		{
			grep("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", pattern)
		}
	default:
		{
			syscallHelp()
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": invalid arch btw \"%v\"\n", args[0])
		}
	}
}
