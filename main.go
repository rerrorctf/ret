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

		for _, cmd := range commands.Commands {
			fmt.Printf("%s ", cmd.Emoji)
			fmt.Printf(theme.ColorBlue+"%s\n"+theme.ColorReset, cmd.Name)
		}

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

	// ida, inscount
	if command[0] == 'i' {
		if len(command) > 1 {
			if command[1] == 'd' {
				util.EnsureSkeleton()
				commands.Ida(flag.Args()[1:])
				return
			}

			if command[1] == 'n' {
				commands.Inscount(flag.Args()[1:])
				return
			}
		}
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

	// ctf, chat, chef, crypto
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

					if strings.Compare("che", command[:3]) == 0 {
						commands.Chef(flag.Args()[1:])
						return
					}
				}
			}

			if command[1] == 'r' {
				commands.Crypto(flag.Args()[1:])
				return
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

	// notes
	if command[0] == 'n' {
		commands.Notes(flag.Args()[1:])
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
