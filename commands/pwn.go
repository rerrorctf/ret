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
	binary := guessBinary()

	script := fmt.Sprintf(
		"#!/usr/bin/env python3\n\n"+
			"#\n# pwn template made with 🚩 https://github.com/rerrorctf/rctf 🚩\n#\n\n"+
			"from pwn import *\n\n"+
			"LOCAL_BINARY = \"./%s\"\n"+
			"REMOTE_IP = \"%s\"\n"+
			"REMOTE_PORT = %d\n\n"+
			"#context.log_level = \"debug\"\n"+
			"context.binary = LOCAL_BINARY\n\n"+
			"#elf = ELF(LOCAL_BINARY)\n"+
			"#libc = elf.libc\n\n"+
			"#p = process(LOCAL_BINARY)\n"+
			"p = remote(REMOTE_IP, REMOTE_PORT)\n"+
			"#gdb.attach(p, gdbscript=\"\")\n\n"+
			"# pwn it here\n\n"+
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

	dockerfile := fmt.Sprintf(
		"#\n# Dockerfile template made with 🚩 https://github.com/rerrorctf/rctf 🚩\n#\n\n"+
			"FROM ubuntu:24.04\n\n"+
			"RUN apt update && apt install -y socat\n\n"+
			"RUN groupadd --gid 1001 pwn\n\n"+
			"RUN useradd --uid 1001 --gid 1001 --home-dir /home/pwn --create-home --shell /sbin/nologin pwn\n\n"+
			"WORKDIR /home/pwn\n\n"+
			"COPY %s .\n\n"+
			"COPY flag.txt .\n\n"+
			"RUN chmod +x ./%s\n\n"+
			"EXPOSE %d\n\n"+
			"USER pwn\n\n"+
			"CMD [\"socat\", \"tcp-listen:%d,fork,reuseaddr\", \"exec:./%s\"]\n",
		binary, binary, port, port, binary)

	err = os.WriteFile("Dockerfile", []byte(dockerfile), 0644)
	if err != nil {
		log.Fatalln("error writing to file:", err)
	}

	compose := fmt.Sprintf(
		"#\n# compose.yml template made with 🚩 https://github.com/rerrorctf/rctf 🚩\n#\n\n"+
			"services:\n"+
			"    task:\n"+
			"        build: .\n"+
			"        ports:\n"+
			"            - %d:%d\n",
		port, port)

	err = os.WriteFile("compose.yml", []byte(compose), 0644)
	if err != nil {
		log.Fatalln("error writing to file:", err)
	}

	fmt.Printf("🐚 "+theme.ColorGray+"ready to pwn:"+theme.ColorReset+" $ sudo docker compose up --build -d && ./%s\n", config.PwnScriptName)
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

	_, err = os.Stat("./Dockerfile")
	if !os.IsNotExist(err) {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": \"Dockerfile\" already exists!\n")
	}

	_, err = os.Stat("./compose.yml")
	if !os.IsNotExist(err) {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": \"Dockerfile\" already exists!\n")
	}

	var ip string
	var port int
	util.GetRemoteParams(args, &ip, &port)

	makeScript(ip, port)
}
