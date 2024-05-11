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
	fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"syscall"+theme.ColorReset+" [(x86/32)/(x64/64)]"+theme.ColorReset+" [regex-pattern]\n")
	fmt.Fprintf(os.Stderr, "  📞 check syscalls by regex with ret\n")

	fmt.Fprintf(os.Stderr, theme.ColorBlue+"\n  uses"+theme.ColorGray+": \n")
	fmt.Fprintf(os.Stderr, theme.ColorGreen+"    x86"+theme.ColorGray+": /usr/include/x86_64-linux-gnu/asm/unistd_32.h"+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, theme.ColorGreen+"    x64"+theme.ColorGray+": /usr/include/x86_64-linux-gnu/asm/unistd_64.h"+theme.ColorReset+"\n")

	fmt.Fprintf(os.Stderr, theme.ColorBlue+"\n  examples"+theme.ColorGray+": \n")
	fmt.Fprintf(os.Stderr, theme.ColorPurple+"    syscall x64 \" 0\""+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, theme.ColorPurple+"    syscall x64 write"+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, theme.ColorPurple+"    syscall 32 read"+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, theme.ColorPurple+"    syscall x86 10[0-9]"+theme.ColorReset+"\n")
}

func grep(path string, pattern string) {
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": opening file %v\n", path)
		os.Exit(1)
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
		os.Exit(1)
	}
}

func Syscall(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			syscallHelp()
			os.Exit(0)
		}
	}

	if len(args) < 2 {
		syscallHelp()
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v missing args\n", 2-len(args))
		os.Exit(1)
	}

	switch args[0] {
	case "x86":
		{
			grep("/usr/include/x86_64-linux-gnu/asm/unistd_32.h", args[1])
		}
	case "32":
		{
			grep("/usr/include/x86_64-linux-gnu/asm/unistd_32.h", args[1])
		}
	case "x64":
		{
			grep("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", args[1])
		}
	case "64":
		{
			grep("/usr/include/x86_64-linux-gnu/asm/unistd_64.h", args[1])
		}
	default:
		{
			syscallHelp()
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": invalid arch \"%v\"\n", args[0])
			os.Exit(1)
		}
	}
}
