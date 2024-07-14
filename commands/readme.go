package commands

import (
	"fmt"
	"os"
	"ret/theme"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "readme",
		Emoji: "🖨️ ",
		Func:  Readme,
		Help:  ReadmeHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/readme.go",
	})
}

func ReadmeHelp() string {
	return "make the readme with ret\n"
}

func Readme(args []string) {
	fmt.Fprintf(os.Stdout, "# ret\n\n")

	fmt.Fprintf(os.Stdout, "<img src=\"https://github.com/rerrorctf/ret/assets/93072266/5a998dbb-5730-4b10-9636-45e35e9fe77e\" alt=\"rounding error ctf team logo\" width=\"400\"/>\n\n")

	fmt.Fprintf(os.Stdout, "## Commands\n\n")

	fmt.Fprintf(os.Stdout, "You can list all the commands by using `-h`, `--help`, `help` or simply providing no arguments:\n\n")

	fmt.Fprintf(os.Stdout, "```\n$ ret help\n```\n\n")

	fmt.Fprintf(os.Stdout, "You can get help for a command by prefixing `help` to the command:\n\n")

	fmt.Fprintf(os.Stdout, "```\n$ ret help command\n```\n\n")

	for _, command := range Commands {
		shortestValidPrefix, restOfCommand := CommandsTrie.ShortestPrefix(command.Name)
		fmt.Fprintf(os.Stdout, "### %s <u>%s</u>%s\n\n", command.Emoji, shortestValidPrefix, restOfCommand)

		fmt.Fprintf(os.Stdout, "```\n$ ret %s ", command.Name)

		for _, arg := range command.Arguments {
			name := arg.Name
			if arg.Default != "" {
				name = fmt.Sprintf("%s=%s", name, arg.Default)
			}

			if arg.List {

				if arg.Optional {
					fmt.Fprintf(os.Stdout, "[%s1 %s2 %s3...] ", name, name, name)
				} else {
					fmt.Fprintf(os.Stdout, "%s1 [%s2 %s3...] ", name, name, name)
				}
			} else {
				if arg.Optional {
					fmt.Fprintf(os.Stdout, "[%s] ", name)
				} else {
					fmt.Fprintf(os.Stdout, "%s ", name)
				}
			}
		}

		fmt.Fprintf(os.Stdout, "\n```\n\n")

		fmt.Fprintf(os.Stdout, "%s\n", theme.RemoveColors(command.Help()))

		fmt.Fprintf(os.Stdout, "🔗 %s\n\n", command.Url)
	}
}
