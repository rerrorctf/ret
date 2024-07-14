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

func init() {
	Commands = append(Commands, Command{
		Name:  "pwn",
		Emoji: "🐚",
		Func:  Pwn,
		Help:  PwnHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/pwn.go",
		Arguments: []Argument{
			{
				Name:     "ip",
				Optional: true,
				List:     false,
			},
			{
				Name:     "port",
				Optional: true,
				List:     false,
			},
		}})
}

func PwnHelp() {
	fmt.Printf("  🐚 create a pwntools script template with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/pwn.go" + theme.ColorReset + "\n")
}

func makePwnScript(ip string, port int) {
	binaries := util.GuessBinary()

	if len(binaries) > 1 {
		fmt.Printf("⚠️ multiple candidate binaries found\n")
		for _, binary := range binaries {
			fmt.Printf("%s\n", binary)
		}
	}

	binary := binaries[0]

	if strings.Compare(binary, config.DefaultBinaryName) != 0 {
		if !util.BinaryIsExecutable(binary) {
			fmt.Printf("⚠️ "+theme.ColorGray+" \""+theme.ColorReset+"%v"+theme.ColorGray+"\""+theme.ColorRed+" is not executable"+theme.ColorReset+"\n", binary)
		}
	}

	var script string

	if len(config.PwnScriptTemplate) > 0 {
		fmt.Printf("🐚 "+theme.ColorGray+"using custom template: \""+theme.ColorCyan+"%s"+theme.ColorGray+"\""+theme.ColorReset+"\n", config.PwnScriptTemplate)
		buf, err := os.ReadFile(config.PwnScriptTemplate)
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": reading \"%s\" %v\n", config.PwnScriptTemplate, err)
		}

		script = string(buf)
		script = strings.ReplaceAll(script, "%BINARY%", binary)
		script = strings.ReplaceAll(script, "%IP%", ip)
		script = strings.ReplaceAll(script, "%PORT%", fmt.Sprintf("%d", port))
	} else {
		script = fmt.Sprintf(
			"#!/usr/bin/env python3\n\n"+
				"from pwn import *\n\n"+
				"#context.log_level = \"debug\"\n"+
				"elf = ELF(\"./%s\", checksec=False)\n"+
				"context.binary = elf\n\n"+
				"#p = elf.process()\n"+
				"#p = elf.debug(gdbscript=\"\")\n"+
				"p = remote(\"%s\", %d)\n\n"+
				"p.interactive()\n",
			binary, ip, port)
	}

	err := os.WriteFile(config.PwnScriptName, []byte(script), 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	err = os.Chmod(config.PwnScriptName, 0744)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	fmt.Printf("🐚 "+theme.ColorGray+"ready to pwn:"+theme.ColorReset+" $ ./%s\n", config.PwnScriptName)
}

func Pwn(args []string) {
	_, err := os.Stat(config.PwnScriptName)
	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", config.PwnScriptName)
	}

	var ip string
	var port int
	util.GetRemoteParams(args, &ip, &port)

	makePwnScript(ip, port)
}
