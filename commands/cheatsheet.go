package commands

import (
	"fmt"
	"os"
	"ret/theme"
)

func Cheatsheet(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"cheatsheet"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  📚 prints a list of cheatsheet links with ret\n")
			os.Exit(0)
		}
	}

	fmt.Println(theme.ColorCyan + "pwndbg" + theme.ColorReset)
	fmt.Println(theme.ColorGray + "🔗 https://cdn.discordapp.com/attachments/1141077572587892857/1174249242882220114/CheatSheet.pdf" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "ghidra" + theme.ColorReset)
	fmt.Println(theme.ColorGray + "🔗 https://ghidra-sre.org/CheatSheet.html" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "linux syscalls" + theme.ColorReset)
	fmt.Println(theme.ColorGray + "🔗 https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "intel sdm" + theme.ColorReset)
	fmt.Println(theme.ColorGray + "🔗 https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "payloads" + theme.ColorReset)
	fmt.Println(theme.ColorGray + "🔗 https://github.com/swisskyrepo/PayloadsAllTheThings" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "reverse shells" + theme.ColorReset)
	fmt.Println(theme.ColorGray + "🔗 https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "gpg" + theme.ColorReset)
	fmt.Println(theme.ColorGray + "🔗 https://irtfweb.ifa.hawaii.edu/~lockhart/gpg/" + theme.ColorReset)
	fmt.Println(theme.ColorGray + "🔗 https://devhints.io/gnupg" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "ssh" + theme.ColorReset)
	fmt.Println(theme.ColorGray + "🔗 https://iximiuz.com/ssh-tunnels/ssh-tunnels.png" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "pwn" + theme.ColorReset)
	fmt.Println(theme.ColorGray + "🔗 https://ir0nstone.gitbook.io/notes/" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "ctf cheatsheet" + theme.ColorReset)
	fmt.Println(theme.ColorGray + "🔗 https://github.com/Rajchowdhury420/CTF-CheatSheet" + theme.ColorReset)
}
