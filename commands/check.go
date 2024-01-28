package commands

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"rctf/config"
	"rctf/theme"
)

func testCommand(command string, args ...string) {
	c := exec.Command(command, args...)
	err := c.Run()
	if err != nil {
		fmt.Printf("  😔 "+theme.ColorRed+"%v %v\n     -> %v"+theme.ColorReset+"\n", command, args, err)
	} else {
		fmt.Printf("  ✅ "+theme.ColorBlue+"%v "+theme.ColorGray+"%v"+theme.ColorReset+"\n", command, args)
	}
}

func Check(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"check"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  ✅ check your env/setup readiness before a ctf with rctf\n")

			os.Exit(0)
		}
	}

	// TODO

	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// system utils
	testCommand("gcc", "--version")
	testCommand("g++", "--version")
	testCommand("clang", "--version")
	testCommand("clang++", "--version")
	testCommand("strace", "--version")
	testCommand("ltrace", "--version")
	testCommand("nasm", "--version")
	testCommand("gdb", "--version")
	testCommand("code", "--version")
	testCommand("subl", "--version")

	// python setup
	testCommand("python3", "--version")
	testCommand("pip", "show", "pwntools")

	// re related stuff
	testCommand("stat", config.GhidraInstallPath+"/ghidraRun")
	testCommand("stat", config.IdaInstallPath+"/idaRun")

	// pwn related stuff
	testCommand("stat", currentUser.HomeDir+"/pwndbg/setup.sh")
	testCommand("one_gadget", "-h")

	// web related stuff
	testCommand("stat", currentUser.HomeDir+"/BurpSuiteCommunity/BurpSuiteCommunity")
	testCommand("stat", "/opt/SecLists")
}
