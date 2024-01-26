package commands

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"rctf/config"
	"rctf/theme"
	"strconv"
)

func getRemoteParams(args []string, ip *string, port *int) {
	scanner := bufio.NewScanner(os.Stdin)

	if len(args) > 0 {
		fmt.Printf("ip: %s\n", args[0])
		*ip = args[0]
	} else {
		fmt.Print("enter the remote ip address (no port): ")
		scanner.Scan()
		*ip = scanner.Text()
	}

	if len(args) > 1 {
		p, err := strconv.Atoi(args[1])

		if err != nil {
			log.Fatalln("💥 "+theme.ColorRed+"error"+theme.ColorReset+": reading port:", err)
		}

		if p < 1 || p > 65535 {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": invalid port %v\n", port)
		}

		fmt.Printf("port: %v\n", p)

		*port = p
	} else {
		fmt.Print("enter the remote port: ")
		scanner.Scan()
		p, err := strconv.Atoi(scanner.Text())

		if err != nil {
			log.Fatalln("💥 "+theme.ColorRed+"error"+theme.ColorReset+": reading port", err)
		}

		if p < 1 || p > 65535 {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": invalid port %v\n", port)
		}

		*port = p
	}
}

func makeScript(ip string, port int) {
	script := fmt.Sprintf(
		"#!/usr/bin/env python3\n\n"+
			"from pwn import *\n\n"+
			"#context.log_level = \"debug\"\n\n"+
			"LOCAL_BINARY = \"./task\"\n"+
			"REMOTE_IP = \"%s\"\n"+
			"REMOTE_PORT = %d\n\n"+
			"#elf = ELF(LOCAL_BINARY)\n\n"+
			"#p = process(LOCAL_BINARY)\n"+
			"p = remote(REMOTE_IP, REMOTE_PORT)\n"+
			"#gdb.attach(p, gdbscript=\"\")\n\n"+
			"# pwn it here\n\n"+
			"p.interactive()\n",
		ip, port)

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
	if config.Verbose {
		fmt.Println("Pwn:", args)
	}

	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, "usage: rctf pwn [ip] [port]\n")
			fmt.Fprintf(os.Stderr, "  🐚 create a pwntools script with rctf\n")
			os.Exit(0)
		}
	}

	_, err := os.Stat(config.PwnScriptName)
	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", config.PwnScriptName)
	}

	var ip string
	var port int
	getRemoteParams(args, &ip, &port)

	makeScript(ip, port)
}
