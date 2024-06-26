package commands

import (
	"fmt"
	"os/exec"
	"os/user"
	"ret/config"
	"ret/theme"
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

func checkHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "check" + theme.ColorReset + "\n")
	fmt.Printf("  ✅ check your env/setup readiness before a ctf with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/check.go" + theme.ColorReset + "\n")
}

func Check(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			checkHelp()
			return
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
	testCommand("unzip")
	testCommand("strings", "-v")
	testCommand("nc", "-h")
	testCommand("ncat", "-h")

	if !testCommand("code", "--version") {
		// note that i symlink codium like this
		// $ ls -lah /usr/local/bin/code
		// lrwxrwxrwx 2 root root 28 May 24 16:32 /usr/local/bin/code -> /usr/share/codium/bin/codium
		suggestLink("https://github.com/VSCodium/vscodium/releases")
	}

	testCommand("nmap", "--version")
	testCommand("jq", "--version")
	testCommand("exiftool", "--version")
	testCommand("xxd", "-v")

	if !testCommand("docker", "-v") {
		suggestLink("https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository")
	}

	if !testCommand("go", "version") {
		suggestLink("https://go.dev/doc/install")
	}

	testCommand("tldr", "--version")

	if !testCommand("shellcheck", "--help") {
		suggestLink("https://github.com/koalaman/shellcheck")
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

	if !testCommand("pin", "-help") {
		suggestLink("https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html")
	}

	testCommand("yara", "--help")

	// wabt
	testCommand("wasm-decompile", "--version")

	// pwn related stuff
	if !testCommand("stat", currentUser.HomeDir+"/pwndbg/setup.sh") {
		suggestLink("https://github.com/pwndbg/pwndbg")
	}

	testCommand("one_gadget", "-h")
	testCommand("pwn")
	testCommand("pwn", "checksec")
	testCommand("ROPgadget", "--h")

	if !testCommand("seccomp-tools", "--version") {
		suggestLink("https://github.com/david942j/seccomp-tools")
	}

	testCommand("patchelf", "-h")

	if !testCommand("msfvenom", "--list", "args") {
		suggestLink("https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html")
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

	// steg related stuff
	testCommand("which", "stegseek")
	testCommand("steghide", "--help")

	// crypto related stuff
	if !testCommand("RsaCtfTool.py", "-h") {
		suggestLink("https://github.com/RsaCtfTool/RsaCtfTool")
	}

	// gcloud
	if !testCommand("gcloud", "--version") {
		suggestLink("https://cloud.google.com/sdk/docs/install#deb")
	}
}
