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
	return "decompress one or more files with ret\n\n" +
		"will first check if the file has a valid extension\n" +
		"valid extensions are " +
		theme.ColorPurple + "`.gzip`" + theme.ColorReset + ", " +
		theme.ColorPurple + "`.gz`" + theme.ColorReset + ", " +
		theme.ColorPurple + "`.zip`" + theme.ColorReset + ", " +
		theme.ColorPurple + "`.xz`" + theme.ColorReset + ", " +
		theme.ColorPurple + "`.7z` " + theme.ColorReset + "and " + theme.ColorPurple + "`.tar`" + theme.ColorReset + "\n\n" +
		"if the file has a valid extension decompress will then check if the file has a valid magic\n\n" +
		"if the file has a valid extension and magic it will be decompressed with 7z as if the following was executed:\n" +
		theme.ColorGray + "$ " + theme.ColorBlue + "7z e filename -y\n" + theme.ColorReset
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
