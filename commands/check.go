package commands

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"rctf/config"
	"rctf/theme"
)

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

func Check(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"check"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  ✅ check your env/setup readiness before a ctf with rctf\n")

			os.Exit(0)
		}
	}

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
	testCommand("vim", "--version")

	if !testCommand("code", "--version") {
		fmt.Println(theme.ColorGray + "       -> 🔗 " + theme.ColorCyan + "https://code.visualstudio.com/" + theme.ColorReset)
	}

	if !testCommand("subl", "--version") {
		fmt.Println(theme.ColorGray + "       -> 🔗 " + theme.ColorCyan + "https://www.sublimetext.com/" + theme.ColorReset)
	}

	testCommand("nmap", "--version")
	testCommand("jq", "--version")
	testCommand("exiftool", "--version")
	testCommand("xxd", "-v")

	if !testCommand("which", "discord") {
		fmt.Println(theme.ColorGray + "       -> 🔗 " + theme.ColorCyan + "https://discord.com/" + theme.ColorReset)
	}

	// python setup
	testCommand("python3", "--version")
	testCommand("pip", "show", "pwntools")

	// re related stuff
	if !testCommand("stat", config.GhidraInstallPath+"/ghidraRun") {
		fmt.Println(theme.ColorGray + "       -> 🔗 " + theme.ColorCyan + "https://github.com/NationalSecurityAgency/ghidra/releases" + theme.ColorReset)
	}

	if !testCommand("stat", config.IdaInstallPath+"/idaRun") {
		fmt.Println(theme.ColorGray + "       -> 🔗 " + theme.ColorCyan + "https://hex-rays.com/ida-free/" + theme.ColorReset)
	}

	// pwn related stuff
	if !testCommand("stat", currentUser.HomeDir+"/pwndbg/setup.sh") {
		fmt.Println(theme.ColorGray + "       -> 🔗 " + theme.ColorCyan + "https://github.com/pwndbg/pwndbg" + theme.ColorReset)
	}

	testCommand("one_gadget", "-h")
	testCommand("pwn")
	testCommand("pwn", "checksec")

	// web related stuff
	if !testCommand("stat", currentUser.HomeDir+"/BurpSuiteCommunity/BurpSuiteCommunity") {
		fmt.Println(theme.ColorGray + "       -> 🔗 " + theme.ColorCyan + "https://portswigger.net/burp/releases/community/latest" + theme.ColorReset)
	}

	if !testCommand("stat", "/opt/SecLists") {
		fmt.Println(theme.ColorGray + "       -> 🔗 " + theme.ColorCyan + "https://github.com/danielmiessler/SecLists/releases" + theme.ColorReset)
	}

	testCommand("gobuster", "-h")
	testCommand("ffuf", "-h")
	testCommand("sqlmap", "-h")
	testCommand("wireshark", "-h")
	testCommand("curl", "--version")

	if !testCommand("docker", "-v") {
		fmt.Println(theme.ColorGray + "       -> 🔗 " + theme.ColorCyan + "https://docs.docker.com/desktop/install/ubuntu/" + theme.ColorReset)
	}

	if !testCommand("go", "version") {
		fmt.Println(theme.ColorGray + "       -> 🔗 " + theme.ColorCyan + "https://go.dev/doc/install" + theme.ColorReset)
	}
}
