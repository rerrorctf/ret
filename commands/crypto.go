package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"ret/config"
	"ret/data"
	"ret/theme"
	"ret/util"
)

func cryptoHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "crypto " + theme.ColorGray + "[file1 file2 file3...]" + theme.ColorReset + "\n")
	fmt.Printf("  🚀 search for crypto constants using yara rules with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/crypto.go" + theme.ColorReset + "\n")
}

func Crypto(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			cryptoHelp()
			return
		}
	}

	jsonData, err := os.ReadFile(config.RetFilesNames)
	if err == nil {
		var files data.Files

		err = json.Unmarshal(jsonData, &files)
		if err == nil {
			for _, file := range files.Files {
				util.CryptoWithYara(file.Filename)
			}
		}
	}

	for _, file := range args {
		util.CryptoWithYara(file)
	}
}
