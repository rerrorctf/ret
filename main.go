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
		fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"command"+theme.ColorGray+" [arg1 arg2...]\n"+theme.ColorReset)

		fmt.Fprintf(os.Stderr, theme.ColorGray+
			"---core------------rev------------pwn------------info------------util-----\n"+
			theme.ColorBlue+
			"🚩 "+theme.StartUnderline+"ct"+theme.StopUnderline+"f          "+
			"🦖 "+theme.StartUnderline+"gh"+theme.StopUnderline+"idra      "+
			"🐚 "+theme.StartUnderline+"p"+theme.StopUnderline+"wn         "+
			"🤝 "+theme.StartUnderline+"ab"+theme.StopUnderline+"i         "+
			"🤏 "+theme.StartUnderline+"de"+theme.StopUnderline+"compress\n"+
			"🔍 "+theme.StartUnderline+"f"+theme.StopUnderline+"ormat       "+
			"💃 "+theme.StartUnderline+"i"+theme.StopUnderline+"da         "+
			"🐋 "+theme.StartUnderline+"do"+theme.StopUnderline+"cker      "+
			"📞 "+theme.StartUnderline+"sy"+theme.StopUnderline+"scall     "+
			"✅ "+theme.StartUnderline+"chec"+theme.StopUnderline+"k\n"+
			"👀 "+theme.StartUnderline+"st"+theme.StopUnderline+"atus                      "+
			"🗽 "+theme.StartUnderline+"l"+theme.StopUnderline+"ibc        "+
			"📚 "+theme.StartUnderline+"chea"+theme.StopUnderline+"tsheet  "+
			"📢 "+theme.StartUnderline+"chat"+theme.StopUnderline+"\n"+
			"📥 "+theme.StartUnderline+"ad"+theme.StopUnderline+"d                                                       "+
			"🧠 "+theme.StartUnderline+"gp"+theme.StopUnderline+"t\n"+
			"🧙 "+theme.StartUnderline+"wi"+theme.StopUnderline+"zard                                                    "+
			"📝 "+theme.StartUnderline+"wr"+theme.StopUnderline+"iteup\n"+
			"🚩 "+theme.ColorGray+"https://github.com/rerrorctf/ret"+theme.ColorBlue+" 🚩                       "+
			"🐙 "+theme.StartUnderline+"gi"+theme.StopUnderline+"st\n"+theme.StopUnderline+theme.ColorReset)
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
