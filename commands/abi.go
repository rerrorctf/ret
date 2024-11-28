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
		Arguments: []Argument{
			{
				Name:     "architecture",
				Optional: true,
				List:     false,
				Default:  "x64",
			},
			{
				Name:     "os",
				Optional: true,
				List:     false,
				Default:  "linux",
			},
		},
	})
}

func AbiHelp() string {
	return "view abi details with ret\n\n" +
		"output includes calling conventions, register volatility and more\n\n" +
		"for architecture specify one of `x86`, `32`, `x64`, `64`, `arm64`, `aapcs64` " + theme.ColorGray + "~ the default is `x64`\n\n" + theme.ColorReset +
		"for os specify one of `linux`, `windows`, `mac` " + theme.ColorGray + "~ the default is `linux`\n\n" + theme.ColorReset +
		"for example:\n" +
		"```bash\n" +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret abi x64 linux\n" + theme.ColorReset +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret abi 32 windows\n" + theme.ColorReset +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret abi am64 mac\n" + theme.ColorReset +
		"```\n"
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

	fmt.Println("\n🔗 " + theme.ColorCyan + "https://www.agner.org/optimize/calling_conventions.pdf" + theme.ColorReset)
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

	fmt.Println("\n🔗 " + theme.ColorCyan + "https://www.agner.org/optimize/calling_conventions.pdf" + theme.ColorReset)
}

func showLinuxAbiAAPCS64() {
	fmt.Println(theme.ColorPurple + "linux 🐧 " + theme.ColorPurple + "AAPCS64" + theme.ColorReset)

	fmt.Println(theme.ColorPurple + "  X31 Stack Pointer " + theme.ColorReset + "(" + theme.ColorPurple + "SP" + theme.ColorReset + ") - " + theme.ColorPurple +
		"X30 Link Register " + theme.ColorReset + "(" + theme.ColorPurple + "LR" + theme.ColorReset + ") - " + theme.ColorPurple +
		"X29 Frame Pointer " + theme.ColorReset + "(" + theme.ColorPurple + "FP" + theme.ColorReset + ")")

	fmt.Println(theme.ColorYellow + "\nscratch" + theme.ColorReset + "/" + theme.ColorYellow + "caller-save" + theme.ColorReset + "/" + theme.ColorYellow + "volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorYellow + "  X9 X10 X11 X12 X13 X14 X15" + theme.ColorReset)

	fmt.Println(theme.ColorGreen + "\ncallee-save" + theme.ColorReset + "/" + theme.ColorGreen + "non-volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorGreen + "  X19 X20 X21 X22 X23 X24 X25 X26 X27 X28" + theme.ColorReset)

	fmt.Println(theme.ColorBlue + "\nintraprocedure" + theme.ColorReset + "/" + theme.ColorBlue + "platform" + theme.ColorReset + ":")

	fmt.Println(theme.ColorBlue + "  X16 " + theme.ColorReset + "(" + theme.ColorBlue + "IP0" + theme.ColorReset + ") - " + theme.ColorBlue +
		"X17 " + theme.ColorReset + "(" + theme.ColorBlue + "IP1" + theme.ColorReset + ") - " + theme.ColorBlue +
		"X18 Platform Register " + theme.ColorReset + "(" + theme.ColorBlue + "PR" + theme.ColorReset + ")")

	fmt.Println(theme.ColorCyan + "\ncall" + theme.ColorReset + ":")

	fmt.Println(theme.ColorCyan + "  X0 X1 X2 X3 X4 X5 X6 X7 STACK => X0 X1 X2 X3 X4 X5 X6 X7" + theme.ColorReset)

	fmt.Println(theme.ColorGray + "  X8 can be used to pass the address location of an indirect result" + theme.ColorReset)

	fmt.Println(theme.ColorGray + "  arguments on the stack should be sign or zero extended and aligned to 8 bytes" + theme.ColorReset)

	fmt.Println(theme.ColorRed + "\nsyscall" + theme.ColorReset + ":" + theme.ColorReset)

	fmt.Println(theme.ColorRed + "  X8 X0 X1 X2 X3 X4 X5 => X0" + theme.ColorReset)
}

func showMacAbiAAPCS64() {
	fmt.Println(theme.ColorPurple + "mac 🍎 " + theme.ColorPurple + "AAPCS64" + theme.ColorReset)

	fmt.Println(theme.ColorPurple + "  X31 Stack Pointer " + theme.ColorReset + "(" + theme.ColorPurple + "SP" + theme.ColorReset + ") - " + theme.ColorPurple +
		"X30 Link Register " + theme.ColorReset + "(" + theme.ColorPurple + "LR" + theme.ColorReset + ") - " + theme.ColorPurple +
		"X29 Frame Pointer " + theme.ColorReset + "(" + theme.ColorPurple + "FP" + theme.ColorReset + ")")

	fmt.Println(theme.ColorGray + "  the frame pointer register (X29) must always address a valid frame record" + theme.ColorReset)

	fmt.Println(theme.ColorYellow + "\nscratch" + theme.ColorReset + "/" + theme.ColorYellow + "caller-save" + theme.ColorReset + "/" + theme.ColorYellow + "volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorYellow + "  X9 X10 X11 X12 X13 X14 X15" + theme.ColorReset)

	fmt.Println(theme.ColorGreen + "\ncallee-save" + theme.ColorReset + "/" + theme.ColorGreen + "non-volatile" + theme.ColorReset + ":")

	fmt.Println(theme.ColorGreen + "  X19 X20 X21 X22 X23 X24 X25 X26 X27 X28" + theme.ColorReset)

	fmt.Println(theme.ColorBlue + "\nintraprocedure" + theme.ColorReset + "/" + theme.ColorBlue + "platform" + theme.ColorReset + ":")

	fmt.Println(theme.ColorBlue + "  X16 " + theme.ColorReset + "(" + theme.ColorBlue + "IP0" + theme.ColorReset + ") - " + theme.ColorBlue +
		"X17 " + theme.ColorReset + "(" + theme.ColorBlue + "IP1" + theme.ColorReset + ") - " + theme.ColorBlue +
		"X18 Platform Register " + theme.ColorReset + "(" + theme.ColorBlue + "PR" + theme.ColorReset + ")")

	fmt.Println(theme.ColorGray + "  the platforms reserve register X18. don't use this register" + theme.ColorReset)

	fmt.Println(theme.ColorCyan + "\ncall" + theme.ColorReset + ":")

	fmt.Println(theme.ColorCyan + "  X0 X1 X2 X3 X4 X5 X6 X7 STACK => X0 X1 X2 X3 X4 X5 X6 X7" + theme.ColorReset)

	fmt.Println(theme.ColorGray + "  X8 can be used to pass the address location of an indirect result" + theme.ColorReset)

	fmt.Println(theme.ColorGray + "  function arguments may consume slots on the stack that are not multiples of 8 bytes" + theme.ColorReset)

	fmt.Println(theme.ColorGray + "  if the total number of bytes for stack-based arguments is not a multiple of 8 bytes, insert padding on the stack to maintain the 8-byte alignment requirements" + theme.ColorReset)

	fmt.Println(theme.ColorPurple + "\nred zone" + theme.ColorReset + ":")

	fmt.Println(theme.ColorReset + "  [" + theme.ColorPurple + "SP" + theme.ColorReset + "/" + theme.ColorPurple + "X31-128" + theme.ColorReset + "] " + theme.ColorPurple +
		"to " + theme.ColorReset + "[" + theme.ColorPurple + "SP" + theme.ColorReset + "/" + theme.ColorPurple + "X31-8" + theme.ColorReset + "]")

	fmt.Println(theme.ColorGray + "  128-byte area below the stack pointer" + theme.ColorReset)

	fmt.Println(theme.ColorGray + "  usermode programs can rely on the bytes below the stack pointer to not change unexpectedly" + theme.ColorReset)

	fmt.Println("\n🔗 " + theme.ColorCyan + "https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms" + theme.ColorReset)
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

	fmt.Println("\n🔗 " + theme.ColorCyan + "https://www.agner.org/optimize/calling_conventions.pdf" + theme.ColorReset)
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

	fmt.Println("\n🔗 " + theme.ColorCyan + "https://www.agner.org/optimize/calling_conventions.pdf" + theme.ColorReset)
}

func Abi(args []string) {
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
	case "arm64", "aapcs64":
		if opsys == "linux" {
			showLinuxAbiAAPCS64()
		} else if opsys == "mac" {
			showMacAbiAAPCS64()
		}
	default:
		{
			log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": unsupported architecture. use 'x86/32', 'x64/64', 'aapcs64/arm64'\n" + theme.ColorReset)
		}
	}
}
