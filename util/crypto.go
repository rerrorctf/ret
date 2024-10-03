package util

import (
	"bytes"
	"embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"ret/theme"
)

//go:embed yara-crypto.yar
var embedFS embed.FS

func CryptoWithYara(file string, buffer *bytes.Buffer) {
	rules, _ := embedFS.ReadFile("yara-crypto.yar")

	tmpfile, _ := os.CreateTemp("", "yara-crypto.yar")
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write(rules); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	if err := tmpfile.Close(); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	cmd := exec.Command("yara", "--no-warnings", "-s", tmpfile.Name(), file)
	cmd.Stdout = buffer
	cmd.Stderr = os.Stderr

	err := cmd.Run()

	if err != nil {
		fmt.Printf("%v\n", err)
	}
}
