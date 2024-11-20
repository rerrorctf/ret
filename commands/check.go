package commands

import (
	"fmt"
	"os/exec"
	"ret/theme"
)

func init() {
	Commands = append(Commands, Command{
		Name:    "check",
		Emoji:   "✅",
		Func:    Check,
		Help:    CheckHelp,
		SeeAlso: []string{"angr", "sage", "docker", "libc"},
	})
}

func CheckHelp() string {
	return "check if ret's optional dependencies are installed\n\n" +
		"checks for the following:\n" +
		theme.ColorGray + "1) " + theme.ColorReset + "docker\n" +
		theme.ColorGray + "2) " + theme.ColorReset + "pwntools\n" +
		theme.ColorGray + "3) " + theme.ColorReset + "ida\n" +
		theme.ColorGray + "4) " + theme.ColorReset + "ghidra\n" +
		theme.ColorGray + "5) " + theme.ColorReset + "gcloud\n"
}

func testCommand(command string, args ...string) bool {
	c := exec.Command(command, args...)
	err := c.Run()
	if err != nil {
		fmt.Printf("  😔 "+theme.ColorRed+"%v %v\n     -> %v"+theme.ColorReset+"\n", command, args, err)
		return false
	}
	fmt.Printf("  ✅ "+theme.ColorBlue+"%v "+theme.ColorGray+"%v"+theme.ColorReset+"\n", command, args)
	return true
}

func suggestLink(link string) {
	fmt.Println(theme.ColorGray + "       -> 🔗 " + theme.ColorCyan + link + theme.ColorReset)
}

func Check(args []string) {
	if !testCommand("docker", "-v") {
		suggestLink("https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository")
	}

	testCommand("pip", "show", "pwntools")

	testCommand("pwn", "checksec")

	if !testCommand("stat", "/opt/ghidra/ghidraRun") {
		suggestLink("https://github.com/NationalSecurityAgency/ghidra/releases")
	}

	if !testCommand("stat", "/opt/ida/ida64") {
		suggestLink("https://hex-rays.com/ida-free/")
	}
}
