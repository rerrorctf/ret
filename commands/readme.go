package commands

import (
	"fmt"
	"reflect"
	"ret/config"
	"ret/theme"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "readme",
		Emoji: "📃",
		Func:  Readme,
		Help:  ReadmeHelp,
	})
}

func ReadmeHelp() string {
	return "make the readme with ret\n"
}

func Readme(args []string) {
	fmt.Printf("# ret\n\n")

	fmt.Printf("<img src=\"https://github.com/rerrorctf/ret/assets/93072266/5a998dbb-5730-4b10-9636-45e35e9fe77e\" alt=\"rounding error ctf team logo\" width=\"400\"/>\n\n")

	fmt.Printf("This tool helps you solve ctf tasks by automating workflow and basic analysis and providing useful utilities.\n\n")

	fmt.Printf("## Installation\n\n")

	fmt.Printf("You can get the latest binary from https://github.com/rerrorctf/ret/releases.\n\n")

	fmt.Printf("Here installation just means putting `ret` somewhere on your path. I like to make a symlink to it in `/usr/local/bin`.\n\n")

	fmt.Printf("```\n$ sudo ln -s ./ret /usr/local/bin/ret\n```\n\n")

	fmt.Printf("Other options are available and you may do whatever works best for you.\n\n")

	fmt.Printf("### Installing Dependencies (Optional)\n\n")

	fmt.Printf("some commands make opportunistic use of other tools and some won't work without them\n\n")

	fmt.Printf("### Compiling (Optional)\n\n")

	fmt.Printf("First install `go` https://go.dev/dl/ by following the install instructions.\n\n")

	fmt.Printf("You can use `go` in system repos but they tend to be fairly old and out of date.\n\n")

	fmt.Printf("Now, the project root directory, you can simply do:\n\n")

	fmt.Printf("```\n$ go build\n```\n\n")

	fmt.Printf("This will produce the `ret` binary. This single file is all you need to use `ret`.\n\n")

	fmt.Printf("There is also a `build.sh` that I use to create the binaries that get uploaded to github.\n\n")

	fmt.Printf("```\n$ ./build.sh\n```\n\n")

	fmt.Printf("## Commands\n\n")

	fmt.Printf("You can list all the commands by using `-h`, `--help`, `help` or simply providing no arguments:\n\n")

	fmt.Printf("```\n$ ret help\n```\n\n")

	fmt.Printf("You can get help for a command by prefixing `help` to the command:\n\n")

	fmt.Printf("```\n$ ret help command\n```\n\n")

	fmt.Printf("---\n\n")

	for _, command := range Commands {
		shortestValidPrefix, restOfCommand := CommandsTrie.ShortestPrefix(command.Name)
		fmt.Printf("### %s <u>%s</u>%s\n\n", command.Emoji, shortestValidPrefix, restOfCommand)

		fmt.Printf("```\n$ ret ")

		for _, arg := range command.Arguments {
			if arg.Override {
				fmt.Printf("%s ", arg.Name)
			}
		}

		fmt.Printf("%s ", command.Name)

		for _, arg := range command.Arguments {
			if arg.Override {
				continue
			}

			name := arg.Name
			if arg.Default != "" {
				name = fmt.Sprintf("%s=%s", name, arg.Default)
			}

			if arg.List {

				if arg.Optional {
					fmt.Printf("[%s1 %s2 %s3...] ", name, name, name)
				} else {
					fmt.Printf("%s1 [%s2 %s3...] ", name, name, name)
				}
			} else {
				if arg.Optional {
					fmt.Printf("[%s] ", name)
				} else {
					fmt.Printf("%s ", name)
				}
			}
		}

		fmt.Printf("\n```\n\n")

		fmt.Printf("%s\n", theme.RemoveColors(command.Help()))

		fmt.Printf("🔗 https://github.com/rerrorctf/ret/blob/main/commands/%s.go\n\n", command.Name)

		fmt.Printf("---\n\n")
	}

	fmt.Printf("## ~/.config/ret\n\n")

	fmt.Printf("`ret` will parse `~/.config/ret`:\n\n")

	fmt.Printf("```json\n{\n")

	t := reflect.TypeOf(config.Config{})

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		if field.Type.String() == "[]string" {
			fmt.Printf("  \"%s\": [%s]", field.Tag.Get("json"), "")
		} else {
			fmt.Printf("  \"%s\": \"%s\"", field.Tag.Get("json"), "")
		}

		if (i + 1) != t.NumField() {
			fmt.Printf(",")
		}

		fmt.Printf("\n")
	}

	fmt.Printf("}\n```\n")
}
