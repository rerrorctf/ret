package commands

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"ret/theme"
)

func init() {
	Commands = append(Commands, Command{
		Name:      "angr",
		Emoji:     "😠",
		Func:      Angr,
		Help:      AngrHelp,
		Url:       "https://github.com/rerrorctf/ret/blob/main/commands/angr.go",
		Arguments: nil})
}

func AngrHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "angr" + theme.ColorReset + "\n")
	fmt.Printf("  😠 open angr with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/angr.go" + theme.ColorReset + "\n")
}

func Angr(args []string) {
	pull := exec.Command("sudo", "docker", "pull", "angr/angr")

	pull.Stdin = os.Stdin
	pull.Stdout = os.Stdout
	pull.Stderr = os.Stderr

	err := pull.Run()
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	dir, err := os.Getwd()
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	run := exec.Command("sudo", "docker", "run", "-it", "-v", fmt.Sprintf("%s:/home/angr/x", dir), "angr/angr")

	run.Stdin = os.Stdin
	run.Stdout = os.Stdout
	run.Stderr = os.Stderr

	err = run.Run()

	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}
