package commands

import (
	"fmt"
	"os"
	"reflect"
	"ret/config"
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

	fmt.Fprintf(os.Stdout, "This tool helps you solve ctf tasks by automating workflow and basic analysis and providing useful utilities.\n\n")

	fmt.Fprintf(os.Stdout, "## Installation\n\n")

	fmt.Fprintf(os.Stdout, "You can get the latest binary from https://github.com/rerrorctf/ret/releases.\n\n")

	fmt.Fprintf(os.Stdout, "Here installation just means putting `ret` somewhere on your path. I like to make a symlink it to in `/usr/local/bin`.\n\n")

	fmt.Fprintf(os.Stdout, "```\n$ sudo ln -s ./ret /usr/local/bin/ret\n```\n\n")

	fmt.Fprintf(os.Stdout, "Other options are available and you may do whatever works best for you.\n\n")

	fmt.Fprintf(os.Stdout, "### Installing Dependencies (Optional)\n\n")

	fmt.Fprintf(os.Stdout, "some commands make opportunistic use of other tools and some won't work without them\n\n")

	fmt.Fprintf(os.Stdout, "consider installing the following to get access to the full functionality of ret\n\n")

	fmt.Fprintf(os.Stdout, "#### yara\n\n")

	fmt.Fprintf(os.Stdout, "yara is used by the crypto and add commands to search for cryptographic constants\n\n")

	fmt.Fprintf(os.Stdout, "#### gcloud cli\n\n")

	fmt.Fprintf(os.Stdout, "the google cloud cli is used by the `vps` command to create and manage compute resources\n\n")

	fmt.Fprintf(os.Stdout, "you can install it from here https://cloud.google.com/sdk/docs/install#deb\n\n")

	fmt.Fprintf(os.Stdout, "#### docker\n\n")

	fmt.Fprintf(os.Stdout, "used by the `docker`, `libc`, `sage` and `angr` commands\n\n")

	fmt.Fprintf(os.Stdout, "you can install it from here https://docs.docker.com/engine/install/ubuntu/#install-using-the-repository\n\n")

	fmt.Fprintf(os.Stdout, "#### pin\n\n")

	fmt.Fprintf(os.Stdout, "used by the output of the `inscount` command\n\n")

	fmt.Fprintf(os.Stdout, "you can install it from here https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html\n\n")

	fmt.Fprintf(os.Stdout, "#### pwntools\n\n")

	fmt.Fprintf(os.Stdout, "used by the output of the `pwn` command\n\n")

	fmt.Fprintf(os.Stdout, "you can install it from here https://docs.pwntools.com/en/stable/install.html\n\n")

	fmt.Fprintf(os.Stdout, "### Compiling (Optional)\n\n")

	fmt.Fprintf(os.Stdout, "First install `go` https://go.dev/dl/ by following the install instructions.\n\n")

	fmt.Fprintf(os.Stdout, "You can use `go` in system repos but they tend to be fairly old and out of date.\n\n")

	fmt.Fprintf(os.Stdout, "Now, the project root directory, you can simply do:\n\n")

	fmt.Fprintf(os.Stdout, "```\n$ go build\n```\n\n")

	fmt.Fprintf(os.Stdout, "This will produce the `ret` binary. This single file is all you need to use `ret`.\n\n")

	fmt.Fprintf(os.Stdout, "There is also a `build.sh` that I use to create the binaries that get uploaded to github.\n\n")

	fmt.Fprintf(os.Stdout, "```\n$ ./build.sh\n```\n\n")

	fmt.Fprintf(os.Stdout, "## Commands\n\n")

	fmt.Fprintf(os.Stdout, "You can list all the commands by using `-h`, `--help`, `help` or simply providing no arguments:\n\n")

	fmt.Fprintf(os.Stdout, "```\n$ ret help\n```\n\n")

	fmt.Fprintf(os.Stdout, "You can get help for a command by prefixing `help` to the command:\n\n")

	fmt.Fprintf(os.Stdout, "```\n$ ret help command\n```\n\n")

	fmt.Fprintf(os.Stdout, "---\n\n")

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

		fmt.Fprintf(os.Stdout, "---\n\n")
	}

	fmt.Fprintf(os.Stdout, "## ~/.config/ret\n\n")

	fmt.Fprintf(os.Stdout, "`ret` will parse `~/.config/ret`:\n\n")

	fmt.Fprintf(os.Stdout, "```json\n{\n")

	t := reflect.TypeOf(config.Config{})

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fmt.Fprintf(os.Stdout, "  \"%s\": \"%s\",\n", field.Tag.Get("json"), "")
	}

	fmt.Fprintf(os.Stdout, "}\n```\n")
}
