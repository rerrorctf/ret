package commands

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"ret/theme"
	"strconv"
	"strings"
)

func inscountHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "inscount " + theme.ColorGray + "file" + theme.ColorReset + "\n")
	fmt.Printf("  🔬 use pin to count instructions with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/inscount.go" + theme.ColorReset + "\n")
}

func Inscount(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			inscountHelp()
			return
		}
	} else {
		inscountHelp()
		return
	}

	flag := ""

	file := args[0]

	cmdArgs := []string{
		"-t", "/opt/pin/source/tools/SimpleExamples/obj-intel64/inscount2_mt.so",
		"--", file,
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
				cmd := exec.Command("/opt/pin/pin", cmdArgs...)

				var cmdStdin bytes.Buffer
				var cmdStdout bytes.Buffer
				var cmdStderr bytes.Buffer

				cmdStdin.WriteString(flag)
				cmdStdin.WriteByte(i)

				cmd.Stdin = &cmdStdin
				cmd.Stdout = &cmdStdout
				cmd.Stderr = &cmdStderr

				_ = cmd.Run()

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

		flag = fmt.Sprintf("%s%c", flag, bestByte)
		fmt.Printf("🔬 %s\n", flag)
	}
}
