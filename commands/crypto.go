package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"ret/config"
	"ret/data"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "crypto",
		Emoji: "🚀",
		Func:  Crypto,
		Help:  CryptoHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/crypto.go",
		Arguments: []Argument{
			{
				Name:     "file",
				Optional: true,
				List:     true,
			},
		}})
}

func CryptoHelp() string {
	return fmt.Sprintf("search for crypto constants using yara rules with ret\n")
}

func Crypto(args []string) {
	jsonData, err := os.ReadFile(config.RetFilesNames)
	if err == nil {
		var files data.Files

		err = json.Unmarshal(jsonData, &files)
		if err == nil {
			for _, file := range files.Files {
				var buffer bytes.Buffer
				util.CryptoWithYara(file.Filepath, &buffer)
				fmt.Printf("%s", buffer.String())
			}
		}
	}

	for _, file := range args {
		var buffer bytes.Buffer
		util.CryptoWithYara(file, &buffer)
		fmt.Printf("%s", buffer.String())
	}
}
