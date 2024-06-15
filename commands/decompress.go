package commands

import (
	"fmt"
	"ret/theme"
	"ret/util"
)

func decompressHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "decompress" + theme.ColorGray + " file1 [file2 file3...]" + theme.ColorReset + "\n")
	fmt.Printf("  🤏 decompress one or more files with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/decompress.go" + theme.ColorReset + "\n")
}

func Decompress(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			decompressHelp()
			return
		default:
			for _, file := range args {
				decompressed := util.DecompressFile(file)

				if decompressed {
					fmt.Printf("🤏 "+theme.ColorGreen+"decompressed"+theme.ColorReset+":\"%s\"\n", file)
				} else {
					fmt.Printf("⚠️ "+theme.ColorYellow+"unable to decompress"+theme.ColorReset+":\"%s\"\n", file)
				}
			}
		}
	} else {
		decompressHelp()
	}
}
