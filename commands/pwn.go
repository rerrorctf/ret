package commands

import (
	"fmt"
	"log"
	"os"
	"ret/config"
	"ret/theme"
	"ret/util"
	"strings"
)

func makeScript(ip string, port int) {
	binary := util.GuessBinary()

	if strings.Compare(binary, util.DefaultBinaryName) != 0 {
		if !util.BinaryIsExecutable(binary) {
			fmt.Printf("⚠️ "+theme.ColorGray+" \""+theme.ColorReset+"%v"+theme.ColorGray+"\""+theme.ColorRed+" is not executable"+theme.ColorReset+"\n", binary)
		}
	}

	script := fmt.Sprintf(
		"#!/usr/bin/env python3\n\n"+
			"from pwn import *\n"+
			"#from z3 import *\n\n"+
			"LOCAL_BINARY = \"./%s\"\n"+
			"REMOTE_IP = \"%s\"\n"+
			"REMOTE_PORT = %d\n\n"+
			"#context.log_level = \"debug\"\n"+
			"elf = ELF(LOCAL_BINARY, checksec=False)\n"+
			"#libc = elf.libc\n"+
			"context.binary = elf\n\n"+
			"p = elf.process()\n"+
			"#p = remote(REMOTE_IP, REMOTE_PORT)\n"+
			"#gdb.attach(p, gdbscript=\"\")\n\n"+
			"p.interactive()\n",
		binary, ip, port)

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
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"pwn"+theme.ColorGray+" [ip] [port]"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  🐚 create a pwntools script template with ret\n")
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
