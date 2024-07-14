package commands

import (
	"fmt"
	"log"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "decompress",
		Emoji: "🤏",
		Func:  Decompress,
		Help:  DecompressHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/decompress.go",
		Arguments: []Argument{
			{
				Name:     "file",
				Optional: false,
				List:     true,
			},
		}})
}

func DecompressHelp() string {
	return fmt.Sprintf("decompress one or more files with ret\n")
}

func Decompress(args []string) {
	if len(args) == 0 {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": expected 1 or more arguments\n")
	}

	for _, file := range args {
		decompressed := util.DecompressFile(file)

		if decompressed {
			fmt.Printf("🤏 "+theme.ColorGreen+"decompressed"+theme.ColorReset+":\"%s\"\n", file)
		} else {
			fmt.Printf("⚠️  "+theme.ColorYellow+"unable to decompress"+theme.ColorReset+":\"%s\"\n", file)
		}
	}
}
