package commands

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"rctf/config"
	"rctf/data"
	"rctf/theme"
	"rctf/util"
	"strings"
)

func guessBinary() string {
	defaultBinaryName := "task"

	jsonData, err := os.ReadFile(config.TaskName)
	if err != nil {
		return defaultBinaryName
	}

	var task data.Task

	err = json.Unmarshal(jsonData, &task)
	if err != nil {
		return defaultBinaryName
	}

	jsonData, err = os.ReadFile(config.RctfFilesName)
	if err != nil {
		return defaultBinaryName
	}

	var files data.Files

	err = json.Unmarshal(jsonData, &files)
	if err != nil {
		return defaultBinaryName
	}

	for _, file := range files.Files {
		if strings.Contains(file.Filename, "libc.so") {
			continue
		}
		return file.Filename
	}

	return defaultBinaryName
}

func makeScript(ip string, port int) {
	script := fmt.Sprintf(
		"#!/usr/bin/env python3\n\n"+
			"#\n# pwn template made with 🚩 https://github.com/rerrorctf/rctf 🚩\n#\n\n"+
			"from pwn import *\n\n"+
			"#context.log_level = \"debug\"\n\n"+
			"LOCAL_BINARY = \"./%s\"\n"+
			"REMOTE_IP = \"%s\"\n"+
			"REMOTE_PORT = %d\n\n"+
			"#elf = ELF(LOCAL_BINARY)\n\n"+
			"#p = process(LOCAL_BINARY)\n"+
			"p = remote(REMOTE_IP, REMOTE_PORT)\n"+
			"#gdb.attach(p, gdbscript=\"\")\n\n"+
			"# pwn it here\n\n"+
			"p.interactive()\n",
		guessBinary(), ip, port)

	err := os.WriteFile(config.PwnScriptName, []byte(script), 0644)
	if err != nil {
		log.Fatalln("error writing to file:", err)
	}

	err = os.Chmod(config.PwnScriptName, 0744)
	if err != nil {
		log.Fatalln("error chmoding file:", err)
	}

	fmt.Printf("🐚 "+theme.ColorGray+"ready to pwn:"+theme.ColorReset+" $ ./%s\n", config.PwnScriptName)
}

func Pwn(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"pwn"+theme.ColorGray+" [ip] [port]"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  🐚 create a pwntools script template with rctf\n")
			os.Exit(0)
		}
	}

	_, err := os.Stat(config.PwnScriptName)
	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", config.PwnScriptName)
	}

	var ip string
	var port int
	util.GetRemoteParams(args, &ip, &port)

	makeScript(ip, port)
}
