package commands

import (
	"fmt"
	"os"
	"rctf/theme"
)

func showLinuxAbix86() {
	fmt.Println(theme.ColorPurple + "linux 🐧 " + theme.ColorPurple + "x86" + theme.ColorReset)

	fmt.Println(theme.ColorYellow + "\nscratch" + theme.ColorReset + "/" + theme.ColorYellow + "caller-save" + theme.ColorReset + "/" + theme.ColorYellow + "volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorYellow + "  EAX ECX EDX XMM0-XMM7 YMM0-YMM7 ZMM0-ZMM7" + theme.ColorReset)

	fmt.Println(theme.ColorGreen + "\ncallee-save" + theme.ColorReset + "/" + theme.ColorGreen + "non-volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorGreen + "  EBX ESI EDI EBP" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "\ncall" + theme.ColorReset + ":")

	fmt.Println(theme.ColorCyan + "  STACK => EAX XMM0 YMM0 ZMM0" + theme.ColorReset)

	fmt.Println(theme.ColorRed + "\nsyscall" + theme.ColorReset + ":" + theme.ColorReset)

	fmt.Println(theme.ColorRed + "  EAX EBX ECX EDX ESI EDI EBP => EAX" + theme.ColorReset)
}

func showLinuxAbix64() {
	fmt.Println(theme.ColorPurple + "\nlinux 🐧 " + theme.ColorPurple + "x64" + theme.ColorReset)

	fmt.Println(theme.ColorYellow + "\nscratch" + theme.ColorReset + "/" + theme.ColorYellow + "caller-save" + theme.ColorReset + "/" + theme.ColorYellow + "volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorYellow + "  RAX RCX RDX RSI RDI R8-R11 XMM0-XMM15 YMM0-YMM15 ZMM0-ZMM31" + theme.ColorReset)

	fmt.Println(theme.ColorGreen + "\ncallee-save" + theme.ColorReset + "/" + theme.ColorGreen + "non-volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorGreen + "  RBX RBP R12-R15" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "\ncall" + theme.ColorReset + ":")

	fmt.Println(theme.ColorCyan + "  RDI RSI RDX RCX R8 R9 XMM0-XMM7 YMM0-YMM7 ZMM0-ZMM7 STACK => RAX RDX XMM0 YMM0 ZMM0" + theme.ColorReset)

	fmt.Println(theme.ColorGray + "  for varargs RAX must indicate the number of XMM registers used" + theme.ColorReset)

	fmt.Println(theme.ColorRed + "\nsyscall" + theme.ColorReset + ":" + theme.ColorReset)

	fmt.Println(theme.ColorRed + "  RAX RDI RSI RDX R10 R8 R9 => RAX" + theme.ColorReset)
}

func showWindowsAbi() {
	fmt.Println(theme.ColorBlue + "\nwindows 🪟 " + theme.ColorBlue + "x86" + theme.ColorReset)

	fmt.Println(theme.ColorBlue + "\nwindows 🪟 " + theme.ColorBlue + "x64" + theme.ColorReset)
}

func Abi(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"abi"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  🤝 view abi details with rctf\n")
			os.Exit(0)
		}
	}

	showLinuxAbix86()

	showLinuxAbix64()

	showWindowsAbi()

	fmt.Println("\n🔗 " + theme.ColorCyan + "https://www.agner.org/optimize/calling_conventions.pdf" + theme.ColorReset)
}
