package main

import (
	"flag"
	"fmt"
	"strings"

	"ret/commands"
	"ret/config"
	"ret/theme"
	"ret/util"
)

var (
	COMMIT = ""
)

func main() {
	flag.Usage = func() {
		fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "command" + theme.ColorGray + " [arg1 arg2...]\n" + theme.ColorReset)

		fmt.Printf(
			theme.ColorBlue +
				"🤝 " + theme.StartUnderline + "ab" + theme.StopUnderline + "i\n" +
				"📥 " + theme.StartUnderline + "ad" + theme.StopUnderline + "d\n" +
				"😠 " + theme.StartUnderline + "an" + theme.StopUnderline + "gr\n" +
				"📢 " + theme.StartUnderline + "chat" + theme.StopUnderline + "\n" +
				"✅ " + theme.StartUnderline + "chec" + theme.StopUnderline + "k\n" +
				"🔪 " + theme.StartUnderline + "chef" + theme.StopUnderline + "\n" +
				"📚 " + theme.StartUnderline + "chea" + theme.StopUnderline + "tsheet\n" +
				"🚩 " + theme.StartUnderline + "ct" + theme.StopUnderline + "f\n" +
				"🤏 " + theme.StartUnderline + "de" + theme.StopUnderline + "compress\n" +
				"🐋 " + theme.StartUnderline + "do" + theme.StopUnderline + "cker\n" +
				"🔍 " + theme.StartUnderline + "f" + theme.StopUnderline + "ormat\n" +
				"🦖 " + theme.StartUnderline + "gh" + theme.StopUnderline + "idra\n" +
				"🐙 " + theme.StartUnderline + "gi" + theme.StopUnderline + "st\n" +
				"🧠 " + theme.StartUnderline + "gp" + theme.StopUnderline + "t\n" +
				"💃 " + theme.StartUnderline + "i" + theme.StopUnderline + "da\n" +
				"🗽 " + theme.StartUnderline + "l" + theme.StopUnderline + "ibc\n" +
				"📡 " + theme.StartUnderline + "pr" + theme.StopUnderline + "oxy\n" +
				"🐚 " + theme.StartUnderline + "pw" + theme.StopUnderline + "n\n" +
				"🌿 " + theme.StartUnderline + "sa" + theme.StopUnderline + "ge\n" +
				"👀 " + theme.StartUnderline + "st" + theme.StopUnderline + "atus\n" +
				"📞 " + theme.StartUnderline + "sy" + theme.StopUnderline + "scall\n" +
				"☁️  " + theme.StartUnderline + "v" + theme.StopUnderline + "ps\n" +
				"🧙 " + theme.StartUnderline + "wi" + theme.StopUnderline + "zard\n" +
				"📝 " + theme.StartUnderline + "wr" + theme.StopUnderline + "iteup\n" +
				theme.StopUnderline + theme.ColorReset)

		fmt.Printf(theme.ColorGray+"https://github.com/rerrorctf/ret ~ %s\n"+theme.ColorReset, COMMIT)
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		return
	}

	config.ParseUserConfig()

	command := flag.Arg(0)

	// format
	if command[0] == 'f' {
		commands.Format(flag.Args()[1:])
		return
	}

	// pwn
	if command[0] == 'p' {
		if len(command) > 1 {
			if command[1] == 'w' {
				commands.Pwn(flag.Args()[1:])
				return
			}

			if command[1] == 'r' {
				commands.Proxy(flag.Args()[1:])
				return
			}
		}
	}

	// docker
	if command[0] == 'd' {
		if len(command) > 1 {
			if command[1] == 'o' {
				commands.Docker(flag.Args()[1:])
				return
			}

			if command[1] == 'e' {
				commands.Decompress(flag.Args()[1:])
				return
			}
		}
	}

	// ghidra, gist
	if command[0] == 'g' {
		if len(command) > 1 {
			if command[1] == 'h' {
				util.EnsureSkeleton()
				commands.Ghidra(flag.Args()[1:])
				return
			}

			if command[1] == 'i' {
				commands.Gist(flag.Args()[1:])
				return
			}

			if command[1] == 'p' {
				commands.Gpt(flag.Args()[1:])
				return
			}
		}
	}

	// ida
	if command[0] == 'i' {
		util.EnsureSkeleton()
		commands.Ida(flag.Args()[1:])
		return
	}

	// add, abi
	if command[0] == 'a' && len(command) > 1 {
		if command[1] == 'd' {
			util.EnsureSkeleton()
			commands.Add(flag.Args()[1:])
			return
		}

		if command[1] == 'b' {
			commands.Abi(flag.Args()[1:])
			return
		}

		if command[1] == 'n' {
			commands.Angr(flag.Args()[1:])
			return
		}
	}

	// status, syscall, sage
	if command[0] == 's' && len(command) > 1 {
		if command[1] == 't' {
			commands.Status(flag.Args()[1:])
			return
		}

		if command[1] == 'y' {
			commands.Syscall(flag.Args()[1:])
			return
		}

		if command[1] == 'a' {
			commands.Sage(flag.Args()[1:])
			return
		}
	}

	// check, cheatsheet, ctf, chat
	if command[0] == 'c' {
		if len(command) > 1 {
			if command[1] == 't' {
				commands.Ctf(flag.Args()[1:])
				return
			}

			if command[1] == 'h' {
				if len(command) > 2 {
					if strings.Compare("cha", command[:3]) == 0 {
						commands.Chat(flag.Args()[1:])
						return
					}
				}
				if len(command) > 3 {
					if strings.Compare("chec", command[:4]) == 0 {
						commands.Check(flag.Args()[1:])
						return
					}

					if strings.Compare("chea", command[:4]) == 0 {
						commands.Cheatsheet(flag.Args()[1:])
						return
					}

					if strings.Compare("chef", command[:4]) == 0 {
						commands.Chef(flag.Args()[1:])
						return
					}
				}
			}
		}
	}

	// writeup, wizard
	if command[0] == 'w' && len(command) > 1 {
		if command[1] == 'r' {
			commands.Writeup(flag.Args()[1:])
			return
		}

		if command[1] == 'i' {
			commands.Wizard(flag.Args()[1:])
			return
		}
	}

	// libc
	if command[0] == 'l' {
		commands.Libc(flag.Args()[1:])
		return
	}

	// vps
	if command[0] == 'v' {
		commands.Vps(flag.Args()[1:])
		return
	}

	// help
	flag.Usage()
}
