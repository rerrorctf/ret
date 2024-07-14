package main

import (
	"flag"
	"fmt"

	"ret/commands"
	"ret/config"
	"ret/theme"
)

var (
	COMMIT = ""
)

func main() {
	commands.PrepareCommands()

	flag.Usage = func() {
		fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "command" + theme.ColorGray + " [arg1 arg2...]\n" + theme.ColorReset)

		for _, cmd := range commands.Commands {
			fmt.Printf("%s ", cmd.Emoji)
			shortestValidPrefix, restOfCommand := commands.CommandsTrie.ShortestPrefix(cmd.Name)
			fmt.Printf(theme.ColorBlue+theme.StartUnderline+"%s"+theme.StopUnderline+"%s\n"+theme.ColorReset, shortestValidPrefix, restOfCommand)
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

	found, cmd := commands.CommandsTrie.Search(command)

	if !found {
		flag.Usage()
		return
	}

	cmd.Func(flag.Args()[1:])
}
