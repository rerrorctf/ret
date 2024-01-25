package commands

import (
	"bufio"
	"fmt"
	"os"
	"rctf/config"
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
			fmt.Println("error reading port:", err)
			os.Exit(1)
		}

		if p < 1 || p > 65535 {
			fmt.Printf("error: invalid port %v\n", port)
			os.Exit(1)
		}

		fmt.Printf("port: %v\n", p)

		*port = p
	} else {
		fmt.Print("enter the remote port: ")
		scanner.Scan()
		p, err := strconv.Atoi(scanner.Text())

		if err != nil {
			fmt.Println("error reading port:", err)
			os.Exit(1)
		}

		if p < 1 || p > 65535 {
			fmt.Printf("error: invalid port %v\n", port)
			os.Exit(1)
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
		fmt.Println("error writing to file:", err)
		os.Exit(1)
	}

	err = os.Chmod(config.PwnScriptName, 0744)
	if err != nil {
		fmt.Println("error chmoding file:", err)
		os.Exit(1)
	}

	fmt.Printf("🐚 ready to pwn: $ ./%s\n", config.PwnScriptName)
}

func Pwn(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
			fmt.Fprintf(os.Stderr, "usage: rctf pwn [ip] [port]\n")

			fmt.Fprintf(os.Stderr, "  create a pwntools script with rctf\n")

			fmt.Fprintf(os.Stderr, "\nsubcommands:\n")
			fmt.Fprintf(os.Stderr, "  ❓ help ~ print this message\n")

			fmt.Fprintf(os.Stderr, "\n~ 🚩 @rerrorctf 🚩 ~\n")
			fmt.Fprintf(os.Stderr, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

			os.Exit(0)
		}
	}

	_, err := os.Stat(config.PwnScriptName)
	if !os.IsNotExist(err) {
		fmt.Printf("💥 error: \"%s\" already exists!\n", config.PwnScriptName)
		os.Exit(1)
	}

	var ip string
	var port int
	getRemoteParams(args, &ip, &port)

	makeScript(ip, port)
}
