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
		Arguments: []Argument{
			{
				Name:     "ip",
				Optional: true,
				List:     false,
				Default:  "127.0.0.1",
			},
			{
				Name:     "port",
				Optional: true,
				List:     false,
				Default:  "9001",
			},
		},
		SeeAlso: []string{"add"}})
}

func PwnHelp() string {
	return "create a pwntools script template with ret\n\n" +
		"the file this command creates is named using " + theme.ColorYellow + "`\"pwnscriptname\"`" + theme.ColorReset + " from " + theme.ColorCyan +
		"`~/.config/ret`" + theme.ColorReset + " and is " + theme.ColorGreen + "`\"go.py\"`" + theme.ColorReset + " by default\n\n" +
		"this command attempts to guess the name of the main task binary using the list of added files and their types\n\n" +
		"you can specify the path of a custom template with " + theme.ColorYellow + "`\"pwnscripttemplate\"`" + theme.ColorReset + "\n\n" +
		"this command will do the follow substitutions in custom templates:\n" +
		theme.ColorGray + "1) " + theme.ColorBlue + "`/%BINARY%/binary`\n" + theme.ColorReset +
		theme.ColorGray + "2) " + theme.ColorBlue + "`/%IP%/ip`\n" + theme.ColorReset +
		theme.ColorGray + "3) " + theme.ColorBlue + "`/%PORT%/port`\n\n" + theme.ColorReset +
		"for example:\n" +
		theme.ColorGray + "1) `\"" + theme.ColorGreen + "remote" + theme.ColorPurple + "(" + theme.ColorRed + "\"" + theme.ColorYellow + "%IP%" + theme.ColorRed +
		"\"" + theme.ColorPurple + ", " + theme.ColorYellow + "%PORT%" + theme.ColorPurple + ")" + theme.ColorGray + "\"` " + theme.ColorReset +
		"would become " +
		theme.ColorGray + "`\"" + theme.ColorGreen + "remote" + theme.ColorPurple + "(" + theme.ColorRed + "\"" + theme.ColorYellow + "127.0.0.1" + theme.ColorRed +
		"\"" + theme.ColorPurple + ", " + theme.ColorYellow + "9001" + theme.ColorPurple + ")" + theme.ColorGray + "\"`\n" + theme.ColorReset +
		theme.ColorGray + "2) `\"" + theme.ColorGreen + "process" + theme.ColorPurple + "(" + theme.ColorRed + "\"" + theme.ColorYellow + "./%BINARY%" + theme.ColorRed +
		"\"" + theme.ColorPurple + ")" + theme.ColorGray + "\"` " + theme.ColorReset +
		"would become " +
		theme.ColorGray + "`\"" + theme.ColorGreen + "process" + theme.ColorPurple + "(" + theme.ColorRed + "\"" + theme.ColorYellow + "./task" + theme.ColorRed +
		"\"" + theme.ColorPurple + ")" + theme.ColorGray + "\"`\n" + theme.ColorReset
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
