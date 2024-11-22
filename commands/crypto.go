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
		Name:  "crypto",
		Emoji: "🚀",
		Func:  Crypto,
		Help:  CryptoHelp,
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
		SeeAlso: []string{}})
}

func CryptoHelp() string {
	return "create a sage script from a template with ret\n\n" +
		"the file this command creates is named using " + theme.ColorYellow + "`\"cryptoscriptname\"`" + theme.ColorReset + " from " + theme.ColorCyan +
		"`~/.config/ret`" + theme.ColorReset + " and is " + theme.ColorGreen + "`\"go.sage\"`" + theme.ColorReset + " by default\n\n" +
		"you can specify the path of a custom template with " + theme.ColorYellow + "`\"cryptoscripttemplate\"`" + theme.ColorReset + "\n\n" +
		"this command will do the follow substitutions in custom templates:\n" +
		theme.ColorGray + "1) " + theme.ColorBlue + "`/%IP%/ip`\n" + theme.ColorReset +
		theme.ColorGray + "2) " + theme.ColorBlue + "`/%PORT%/port`\n\n" + theme.ColorReset +
		"for example:\n" +
		theme.ColorGray + "`\"" + theme.ColorGreen + "remote" + theme.ColorPurple + "(" + theme.ColorRed + "\"" + theme.ColorYellow + "%IP%" + theme.ColorRed +
		"\"" + theme.ColorPurple + ", " + theme.ColorYellow + "%PORT%" + theme.ColorPurple + ")" + theme.ColorGray + "\"` " + theme.ColorReset +
		"would become " +
		theme.ColorGray + "`\"" + theme.ColorGreen + "remote" + theme.ColorPurple + "(" + theme.ColorRed + "\"" + theme.ColorYellow + "127.0.0.1" + theme.ColorRed +
		"\"" + theme.ColorPurple + ", " + theme.ColorYellow + "9001" + theme.ColorPurple + ")" + theme.ColorGray + "\"`\n" + theme.ColorReset
}

func makeCryptoScript(ip string, port int) {
	var script string

	if len(config.CryptoScriptTemplate) > 0 {
		fmt.Printf("🚀 "+theme.ColorGray+"using custom template: \""+theme.ColorCyan+"%s"+theme.ColorGray+"\""+theme.ColorReset+"\n", config.CryptoScriptTemplate)
		buf, err := os.ReadFile(config.CryptoScriptTemplate)
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": reading \"%s\" %v\n", config.CryptoScriptTemplate, err)
		}

		script = string(buf)
		script = strings.ReplaceAll(script, "%IP%", ip)
		script = strings.ReplaceAll(script, "%PORT%", fmt.Sprintf("%d", port))
	} else {
		script = "#!/usr/bin/env sage\n\n" +
			"from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes\n\n"
	}

	err := os.WriteFile(config.CryptoScriptName, []byte(script), 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	err = os.Chmod(config.CryptoScriptName, 0744)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	fmt.Printf("🚀 "+theme.ColorGray+"ready to cry:"+theme.ColorReset+" $ ./%s\n", config.CryptoScriptName)
}

func Crypto(args []string) {
	_, err := os.Stat(config.CryptoScriptName)
	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", config.CryptoScriptName)
	}

	var ip string
	var port int
	util.GetRemoteParams(args, &ip, &port)

	makeCryptoScript(ip, port)
}
