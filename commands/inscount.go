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
		Name:      "inscount",
		Emoji:     "🔬",
		Func:      Inscount,
		Help:      InscountHelp,
		Url:       "https://github.com/rerrorctf/ret/blob/main/commands/inscount.go",
		Arguments: nil})
}

func makeInscountGoScript(binary string) {
	script := fmt.Sprintf(
		`package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

const (
	PIN             = "/opt/pin/pin"
	INSCOUNT2_MT_SO = "/opt/pin/source/tools/SimpleExamples/obj-intel64/inscount2_mt.so"
	BINARY          = "./%s"
)

func main() {
	flag := ""

	cmdArgs := []string{
		"-t", INSCOUNT2_MT_SO,
		"--", BINARY,
	}

	var printableBytes []byte
	for i := 32; i <= 126; i++ {
		printableBytes = append(printableBytes, byte(i))
	}

	highestCount := 0
	var bestByte byte

	type Result struct {
		count    int
		bestByte byte
	}

	results := make(chan Result)

	for {
		for _, i := range printableBytes {
			go func(i byte) {
				cmd := exec.Command(PIN, cmdArgs...)

				var cmdStdin bytes.Buffer
				var cmdStdout bytes.Buffer
				var cmdStderr bytes.Buffer

				cmdStdin.WriteString(flag)
				cmdStdin.WriteByte(i)

				cmd.Stdin = &cmdStdin
				cmd.Stdout = &cmdStdout
				cmd.Stderr = &cmdStderr

				err := cmd.Run()

				if err != nil {
					fmt.Printf("%%s\n", cmdStdout.String())
					fmt.Printf("%%s\n", cmdStderr.String())
				}

				totalCount := 0
				scanner := bufio.NewScanner(&cmdStdout)
				for scanner.Scan() {
					line := scanner.Text()
					if strings.HasPrefix(line, "Count[") {
						parts := strings.Split(line, " = ")
						count, err := strconv.Atoi(parts[1])
						if err == nil {
							totalCount += count
						}
					}
				}

				results <- Result{totalCount, i}
			}(i)
		}

		for range printableBytes {
			result := <-results
			if result.count > highestCount {
				highestCount = result.count
				bestByte = result.bestByte
			}
		}

		flag = fmt.Sprintf("%%s%%c", flag, bestByte)
		fmt.Printf("%%s\n", flag)
	}
}
`, binary)

	err := os.WriteFile(config.InscountGoScriptName, []byte(script), 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	fmt.Printf("🔬 "+theme.ColorGray+"ready to count instructions with golang:"+theme.ColorReset+" $ go run ./%s\n", config.InscountGoScriptName)
}

func makeInscountPythonScript(binary string) {
	script := fmt.Sprintf(
		`#!/usr/bin/env python3

import string
from pwn import *

PIN             = "/opt/pin/pin"
INSCOUNT2_MT_SO = "/opt/pin/source/tools/SimpleExamples/obj-intel64/inscount2_mt.so"
BINARY          = "./%s"

flag = b""

while True:
	highest_count = 0
	best_byte = b"\x00"
	for c in string.printable:
		b = c.encode()
		with process(argv=[PIN, "-t", INSCOUNT2_MT_SO, "--", BINARY], level="CRITICAL") as p:
			p.sendline(flag + b)

			lines = p.recvall().split(b"\n")

			count = 0
			for line in lines:
				if b"Count[" in line:
					count += int(line.split(b" = ")[1])

			if count > highest_count:
				highest_count = count
				best_byte = b
	flag += best_byte
	log.success(flag.decode())
`, binary)

	err := os.WriteFile(config.InscountPythonScriptName, []byte(script), 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	err = os.Chmod(config.InscountPythonScriptName, 0744)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	fmt.Printf("🔬 "+theme.ColorGray+"ready to count instructions with python:"+theme.ColorReset+" $ ./%s\n", config.InscountPythonScriptName)
}

func InscountHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "inscount" + theme.ColorReset + "\n")
	fmt.Printf("  🔬 create a pin script to count instructions from a template with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/inscount.go" + theme.ColorReset + "\n")
}

func Inscount(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			InscountHelp()
			return
		}
	}

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

	_, err := os.Stat(config.InscountGoScriptName)
	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", config.InscountGoScriptName)
	}

	makeInscountGoScript(binary)

	_, err = os.Stat(config.InscountPythonScriptName)
	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\" already exists!\n", config.InscountPythonScriptName)
	}

	makeInscountPythonScript(binary)
}
