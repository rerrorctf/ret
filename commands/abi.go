package commands

import (
	"fmt"
	"log"
	"ret/theme"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "abi",
		Emoji: "🤝",
		Func:  Abi,
		Help:  AbiHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/abi.go",
		Arguments: []Argument{
			{
				Name:     "architecture",
				Optional: true,
				List:     false,
			},
			{
				Name:     "os",
				Optional: true,
				List:     false,
			},
		},
	})
}

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
	fmt.Println(theme.ColorPurple + "linux 🐧 " + theme.ColorPurple + "x64" + theme.ColorReset)

	fmt.Println(theme.ColorYellow + "\nscratch" + theme.ColorReset + "/" + theme.ColorYellow + "caller-save" + theme.ColorReset + "/" + theme.ColorYellow + "volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorYellow + "  RAX RCX RDX RSI RDI R8-R11 XMM0-XMM15 YMM0-YMM15 ZMM0-ZMM31" + theme.ColorReset)

	fmt.Println(theme.ColorGreen + "\ncallee-save" + theme.ColorReset + "/" + theme.ColorGreen + "non-volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorGreen + "  RBX RBP R12-R15" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "\ncall" + theme.ColorReset + ":")

	fmt.Println(theme.ColorCyan + "  RDI RSI RDX RCX R8 R9 XMM0-XMM7 YMM0-YMM7 ZMM0-ZMM7 STACK => RAX RDX XMM0 YMM0 ZMM0" + theme.ColorReset)

	fmt.Println(theme.ColorGray + "  for varargs RAX must indicate the number of XMM registers used" + theme.ColorReset)

	fmt.Println(theme.ColorRed + "\nsyscall" + theme.ColorReset + ":" + theme.ColorReset)

	fmt.Println(theme.ColorRed + "  RAX RDI RSI RDX R10 R8 R9 => RAX" + theme.ColorReset)

	fmt.Println(theme.ColorPurple + "\nred zone" + theme.ColorReset + ":")

	fmt.Println(theme.ColorPurple + "  [rsp-128] to [rsp-8]" + theme.ColorReset)

	fmt.Println(theme.ColorGray + "  128-byte area below the stack pointer see -mno-red-zone" + theme.ColorReset)
}

func showWindowsAbix86() {
	fmt.Println(theme.ColorBlue + "windows 🪟 " + theme.ColorBlue + "x86" + theme.ColorReset)

	fmt.Println(theme.ColorYellow + "\nscratch" + theme.ColorReset + "/" + theme.ColorYellow + "caller-save" + theme.ColorReset + "/" + theme.ColorYellow + "volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorYellow + "  EAX ECX EDX XMM0-XMM7 YMM0-YMM7 ZMM0-ZMM7" + theme.ColorReset)

	fmt.Println(theme.ColorGreen + "\ncallee-save" + theme.ColorReset + "/" + theme.ColorGreen + "non-volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorGreen + "  EBX ESI EDI EBP" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "\ncall" + theme.ColorReset + ":")

	fmt.Println(theme.ColorCyan + "  STACK => EAX EDX XMM0 YMM0 ZMM0" + theme.ColorReset)

	fmt.Println(theme.ColorGray + "  for fastcall the first two parameters use ECX EDX" + theme.ColorReset)
}

func showWindowsAbix64() {
	fmt.Println(theme.ColorBlue + "windows 🪟 " + theme.ColorBlue + "x64" + theme.ColorReset)

	fmt.Println(theme.ColorYellow + "\nscratch" + theme.ColorReset + "/" + theme.ColorYellow + "caller-save" + theme.ColorReset + "/" + theme.ColorYellow + "volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorYellow + "  RAX RCX RDX R8-R11 XMM0-XMM5 YMM0-YMM15 ZMM0-ZMM31" + theme.ColorReset)

	fmt.Println(theme.ColorGreen + "\ncallee-save" + theme.ColorReset + "/" + theme.ColorGreen + "non-volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorGreen + "  RBX RSI RDI RBP R12-R15 XMM6-XMM15" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "\ncall" + theme.ColorReset + ":")

	fmt.Println(theme.ColorCyan + "  RCX/ZMM0 RDX/ZMM1 R8/ZMM2 R9/ZMM3 STACK => RAX XMM0 YMM0 ZMM0" + theme.ColorReset)

	fmt.Println(theme.ColorPurple + "\nshadow space" + theme.ColorReset + ":")

	fmt.Println(theme.ColorPurple + "  [rsp+8] to [rsp+32]" + theme.ColorReset)

	fmt.Println(theme.ColorGray + "  callers must reserve 32 bytes of storage space after the return address" + theme.ColorReset)
}

func AbiHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "abi" + theme.ColorReset + " [architecture] [os]\n")
	fmt.Printf("  🤝 view abi details with ret\n")
	fmt.Printf("  architecture: " + theme.ColorYellow + "x86/32" + theme.ColorReset + " or " + theme.ColorYellow + "x64/64" + theme.ColorReset + "\n")
	fmt.Printf("  os: " + theme.ColorYellow + "linux" + theme.ColorReset + " or " + theme.ColorYellow + "windows" + theme.ColorReset + "\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/abi.go" + theme.ColorReset + "\n")
}

func Abi(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			AbiHelp()
			return
		}
	}

	arch := "x64"
	opsys := "linux"

	if len(args) > 1 {
		arch = args[0]
		opsys = args[1]
	} else if len(args) > 0 {
		arch = args[0]
	}

	switch arch {
	case "x86", "32":
		if opsys == "linux" {
			showLinuxAbix86()
		} else {
			showWindowsAbix86()
		}
	case "x64", "64":
		if opsys == "linux" {
			showLinuxAbix64()
		} else {
			showWindowsAbix64()
		}
	default:
		{
			log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": unsupported architecture. use 'x86/32' or 'x64/64'\n" + theme.ColorReset)
		}
	}

	fmt.Println("\n🔗 " + theme.ColorCyan + "https://www.agner.org/optimize/calling_conventions.pdf" + theme.ColorReset)
}
