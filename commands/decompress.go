package commands

import (
	"fmt"
	"os"
	"ret/theme"
	"ret/util"
)

func decompressHelp() {
	fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"decompress"+theme.ColorGray+" file1 [file2 file3...]"+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, "  🤏 decompress one or more files with ret\n")
	fmt.Fprintf(os.Stderr, "  🔗 "+theme.ColorGray+"https://github.com/rerrorctf/ret/blob/main/commands/decompress.go"+theme.ColorReset+"\n")
	os.Exit(0)
}

func Decompress(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			decompressHelp()
			os.Exit(0)
		default:
			for _, file := range args {
				util.DecompressFile(file)
			}
		}
	} else {
		decompressHelp()
		os.Exit(1)
	}
}
