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
		Url:       "https://github.com/rerrorctf/ret/blob/main/commands/sage.go",
		Arguments: nil})
}

func SageHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "sage" + theme.ColorReset + "\n")
	fmt.Printf("  🌿 open sage with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/sage.go" + theme.ColorReset + "\n")
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
