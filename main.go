package main

import (
	"flag"
	"fmt"
	"os"

	"rctf/commands"
	"rctf/config"
	"rctf/theme"
	"rctf/util"
)

func main() {
	flag.BoolVar(&config.Verbose, "v", false, "enable verbose mode")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"command"+theme.ColorGray+" [arg1 arg2...]\n"+theme.ColorReset)

		flag.PrintDefaults()

		fmt.Fprintf(os.Stderr, theme.ColorGreen+"commands"+theme.ColorReset+":\n")
		fmt.Fprintf(os.Stderr, "  ⛳ "+theme.ColorBlue+"flag"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  👀 "+theme.ColorBlue+"status"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📥 "+theme.ColorBlue+"add"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🐚 "+theme.ColorBlue+"pwn"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🐋 "+theme.ColorBlue+"docker"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🦖 "+theme.ColorBlue+"ghidra"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  💃 "+theme.ColorBlue+"ida"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  ✅ "+theme.ColorBlue+"check"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📞 "+theme.ColorBlue+"syscall"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📝 "+theme.ColorBlue+"writeup"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📚 "+theme.ColorBlue+"cheatsheet"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🧙 "+theme.ColorBlue+"wizard"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "\n🚩 https://github.com/rerrorctf/rctf 🚩\n")
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	config.ParseUserConfig()

	switch flag.Arg(0) {
	case "flag":
		commands.Flag(flag.Args()[1:])
	case "add":
		util.EnsureSkeleton()
		commands.Add(flag.Args()[1:])
	case "status":
		commands.Status(flag.Args()[1:])
	case "pwn":
		commands.Pwn(flag.Args()[1:])
	case "docker":
		commands.Docker(flag.Args()[1:])
	case "ghidra":
		util.EnsureSkeleton()
		commands.Ghidra(flag.Args()[1:])
	case "ida":
		util.EnsureSkeleton()
		commands.Ida(flag.Args()[1:])
	case "check":
		commands.Check(flag.Args()[1:])
	case "syscall":
		commands.Syscall(flag.Args()[1:])
	case "writeup":
		commands.Writeup(flag.Args()[1:])
	case "cheatsheet":
		commands.Cheatsheet(flag.Args()[1:])
	case "wizard":
		commands.Wizard(flag.Args()[1:])
	default:
		flag.Usage()
		os.Exit(1)
	}
}
