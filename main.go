package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"ret/commands"
	"ret/config"
	"ret/theme"
	"ret/util"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"command"+theme.ColorGray+" [arg1 arg2...]\n\n"+theme.ColorReset)

		fmt.Fprintf(os.Stderr, theme.ColorGreen+"commands"+theme.ColorReset+":\n")
		fmt.Fprintf(os.Stderr, "  ⛳ "+theme.ColorBlue+"flag"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🧙 "+theme.ColorBlue+"wizard"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📥 "+theme.ColorBlue+"add"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  👀 "+theme.ColorBlue+"status"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🐚 "+theme.ColorBlue+"pwn"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🦖 "+theme.ColorBlue+"ghidra"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  💃 "+theme.ColorBlue+"ida"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🐋 "+theme.ColorBlue+"docker"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  ✅ "+theme.ColorBlue+"check"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📞 "+theme.ColorBlue+"syscall"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🤝 "+theme.ColorBlue+"abi"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📝 "+theme.ColorBlue+"writeup"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📚 "+theme.ColorBlue+"cheatsheet"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "\n🚩 https://github.com/rerrorctf/ret 🚩\n")
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	config.ParseUserConfig()

	command := flag.Arg(0)

	// flag
	if command[0] == 'f' {
		commands.Flag(flag.Args()[1:])
		return
	}

	// pwn
	if command[0] == 'p' {
		commands.Pwn(flag.Args()[1:])
		return
	}

	// docker
	if command[0] == 'd' {
		commands.Docker(flag.Args()[1:])
		return
	}

	// ghidra
	if command[0] == 'g' {
		util.EnsureSkeleton()
		commands.Ghidra(flag.Args()[1:])
		return
	}

	// ida
	if command[0] == 'i' {
		util.EnsureSkeleton()
		commands.Ida(flag.Args()[1:])
		return
	}

	// add, abi
	if command[0] == 'a' && len(command) > 1 {
		if command[1] == 'd' {
			util.EnsureSkeleton()
			commands.Add(flag.Args()[1:])
			return
		}

		if command[1] == 'b' {
			commands.Abi(flag.Args()[1:])
			return
		}
	}

	// status, syscall
	if command[0] == 's' && len(command) > 1 {
		if command[1] == 't' {
			commands.Status(flag.Args()[1:])
			return
		}

		if command[1] == 'y' {
			commands.Syscall(flag.Args()[1:])
			return
		}
	}

	// check, cheatsheet
	if command[0] == 'c' && len(command) > 3 {
		if strings.Compare("chec", command[:4]) == 0 {
			commands.Check(flag.Args()[1:])
			return
		}

		if strings.Compare("chea", command[:4]) == 0 {
			commands.Cheatsheet(flag.Args()[1:])
			return
		}
	}

	// writeup, wizard
	if command[0] == 'w' && len(command) > 1 {
		if command[1] == 'r' {
			commands.Writeup(flag.Args()[1:])
			return
		}

		if command[1] == 'i' {
			commands.Wizard(flag.Args()[1:])
			return
		}
	}

	// help
	flag.Usage()
	os.Exit(1)
}
