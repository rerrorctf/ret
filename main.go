package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"rctf/commands"
	"rctf/config"
	"rctf/data"
	"rctf/theme"
	"rctf/util"
)

func parseUserConfig() {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	configPath := filepath.Join(currentUser.HomeDir, config.UserConfig)

	jsonData, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	var userConfig data.Config

	err = json.Unmarshal(jsonData, &userConfig)
	if err != nil {
		fmt.Println("error unmarshalling json:", err)
		os.Exit(1)
	}

	if len(userConfig.GhidraInstallPath) > 0 {
		config.GhidraInstallPath = userConfig.GhidraInstallPath
	}

	if len(userConfig.GhidraProjectPath) > 0 {
		config.GhidraProjectPath = userConfig.GhidraProjectPath
	}

	if len(userConfig.IdaInstallPath) > 0 {
		config.IdaInstallPath = userConfig.IdaInstallPath
	}

	if len(userConfig.IdaProjectPath) > 0 {
		config.IdaProjectPath = userConfig.IdaProjectPath
	}

	if len(userConfig.PwnScriptName) > 0 {
		config.PwnScriptName = userConfig.PwnScriptName
	}
}

func main() {
	flag.BoolVar(&config.Verbose, "v", false, "enable verbose mode")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"command"+theme.ColorGray+" [arg1 arg2...]\n"+theme.ColorReset)

		flag.PrintDefaults()

		fmt.Fprintf(os.Stderr, theme.ColorGreen+"commands"+theme.ColorReset+":\n")
		fmt.Fprintf(os.Stderr, "  🚀 "+theme.ColorBlue+"init"+theme.ColorReset+"\n")
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

	parseUserConfig()

	switch flag.Arg(0) {
	case "init":
		util.EnsureSkeleton()
		commands.Init(flag.Args()[1:])
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
