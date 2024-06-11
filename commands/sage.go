package commands

import (
	"fmt"
	"os"
	"os/exec"
	"ret/theme"
)

func sageHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "sage" + theme.ColorReset + "\n")
	fmt.Printf("  🌿 open sage with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/sage.go" + theme.ColorReset + "\n")
}

func Sage(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			sageHelp()
			os.Exit(1)
		}
	}

	pull := exec.Command("sudo", "docker", "pull", "sagemath/sagemath")

	pull.Stdin = os.Stdin
	pull.Stdout = os.Stdout
	pull.Stderr = os.Stderr

	err := pull.Run()
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	run := exec.Command("sudo", "docker", "run", "-it", "sagemath/sagemath:latest")

	run.Stdin = os.Stdin
	run.Stdout = os.Stdout
	run.Stderr = os.Stderr

	err = run.Run()

	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
}
