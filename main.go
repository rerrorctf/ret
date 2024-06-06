package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"ret/commands"
	"ret/config"
	"ret/theme"
	"ret/util"
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"command"+theme.ColorGray+" [arg1 arg2...]\n\n"+theme.ColorReset)

		fmt.Fprintf(os.Stderr, theme.ColorGreen+"commands"+theme.ColorReset+":\n")
		fmt.Fprintf(os.Stderr, "  🚩 "+theme.ColorBlue+"ctf"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🔍 "+theme.ColorBlue+"format"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🧙 "+theme.ColorBlue+"wizard"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📥 "+theme.ColorBlue+"add"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🤏 "+theme.ColorBlue+"decompress"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  👀 "+theme.ColorBlue+"status"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🐚 "+theme.ColorBlue+"pwn"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🦖 "+theme.ColorBlue+"ghidra"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  💃 "+theme.ColorBlue+"ida"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🐋 "+theme.ColorBlue+"docker"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🗽 "+theme.ColorBlue+"libc"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  ✅ "+theme.ColorBlue+"check"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📞 "+theme.ColorBlue+"syscall"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🤝 "+theme.ColorBlue+"abi"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📢 "+theme.ColorBlue+"chat"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  🐙 "+theme.ColorBlue+"gist"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📝 "+theme.ColorBlue+"writeup"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "  📚 "+theme.ColorBlue+"cheatsheet"+theme.ColorReset+"\n")
		fmt.Fprintf(os.Stderr, "\n🚩 https://github.com/rerrorctf/ret 🚩\n")
	}

	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
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
		commands.Pwn(flag.Args()[1:])
		return
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
	}

	// status, syscall
	if command[0] == 's' && len(command) > 1 {
		if command[1] == 't' {
			commands.Status(flag.Args()[1:])
			return
		}

		if command[1] == 'y' {
			commands.Syscall(flag.Args()[1:])
			return
		}
	}

	// check, cheatsheet, ctf, chat
	if command[0] == 'c' {
		if len(command) > 1 {
			if command[1] == 't' {
				util.EnsureSkeleton()
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

	// help
	flag.Usage()
	os.Exit(1)
}
