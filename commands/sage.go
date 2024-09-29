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
		Name:      "sage",
		Emoji:     "🌿",
		Func:      Sage,
		Help:      SageHelp,
		Arguments: nil})
}

func SageHelp() string {
	return fmt.Sprintf("open sage with ret\n")
}

func Sage(args []string) {
	pull := exec.Command("sudo", "docker", "pull", "sagemath/sagemath")

	pull.Stdin = os.Stdin
	pull.Stdout = os.Stdout
	pull.Stderr = os.Stderr

	err := pull.Run()
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	run := exec.Command("sudo", "docker", "run", "-it", "sagemath/sagemath:latest")

	run.Stdin = os.Stdin
	run.Stdout = os.Stdout
	run.Stderr = os.Stderr

	err = run.Run()

	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}
