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

func suggestLink(link string) {
	fmt.Println(theme.ColorGray + "       -> 🔗 " + theme.ColorCyan + link + theme.ColorReset)
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
		suggestLink("https://code.visualstudio.com/")
	}

	if !testCommand("subl", "--version") {
		suggestLink("https://www.sublimetext.com/")
	}

	testCommand("nmap", "--version")
	testCommand("jq", "--version")
	testCommand("exiftool", "--version")
	testCommand("xxd", "-v")

	if !testCommand("which", "discord") {
		suggestLink("https://discord.com/")
	}

	// python setup
	testCommand("python3", "--version")
	testCommand("pip", "show", "pwntools")

	// re related stuff
	if !testCommand("stat", config.GhidraInstallPath+"/ghidraRun") {
		suggestLink("https://github.com/NationalSecurityAgency/ghidra/releases")
	}

	if !testCommand("stat", config.IdaInstallPath+"/ida64") {
		suggestLink("https://hex-rays.com/ida-free/")
	}

	// pwn related stuff
	if !testCommand("stat", currentUser.HomeDir+"/pwndbg/setup.sh") {
		suggestLink("https://github.com/pwndbg/pwndbg")
	}

	testCommand("one_gadget", "-h")
	testCommand("pwn")
	testCommand("pwn", "checksec")

	if !testCommand("seccomp-tools", "--version") {
		suggestLink("https://github.com/david942j/seccomp-tools")
	}

	// web related stuff
	if !testCommand("stat", currentUser.HomeDir+"/BurpSuiteCommunity/BurpSuiteCommunity") {
		suggestLink("https://portswigger.net/burp/releases/community/latest")
	}

	if !testCommand("stat", "/opt/SecLists") {
		suggestLink("https://github.com/danielmiessler/SecLists/releases")
	}

	testCommand("gobuster", "-h")
	testCommand("ffuf", "-h")
	testCommand("sqlmap", "-h")
	testCommand("wireshark", "-h")
	testCommand("curl", "--version")

	if !testCommand("docker", "-v") {
		suggestLink("https://docs.docker.com/desktop/install/ubuntu/")
	}

	if !testCommand("go", "version") {
		suggestLink("https://go.dev/doc/install")
	}

	// steg related stuff
	testCommand("which", "stegseek")
	testCommand("steghide", "--help")
}
