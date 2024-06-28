package commands

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"ret/config"
	"ret/data"
	"ret/theme"
)

//go:embed yara-crypto.yar
var embedFS embed.FS

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

	rules, _ := embedFS.ReadFile("yara-crypto.yar")

	tmpfile, _ := os.CreateTemp("", "yara-crypto.yar")
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(rules); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	if err := tmpfile.Close(); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	jsonData, err := os.ReadFile(config.RetFilesNames)
	if err == nil {
		var files data.Files

		err = json.Unmarshal(jsonData, &files)
		if err == nil {
			for _, file := range files.Files {
				cmd := exec.Command("yara", "--no-warnings", "-s", tmpfile.Name(), file.Filepath)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.Run()
			}
		}
	}

	for _, file := range args {
		cmd := exec.Command("yara", "--no-warnings", "-s", tmpfile.Name(), file)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
}
