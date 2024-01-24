package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"rctf/config"
)

func AddHelp() {
	fmt.Println("rctf add help would go here...")
}

func copyFile(srcPath string, dstPath string) error {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}

	return nil
}

func addFile(srcPath string) error {
	_, fileName := filepath.Split(srcPath)

	dstPath := config.FilesFolderName + "/" + fileName

	err := copyFile(srcPath, dstPath)
	if err != nil {
		fmt.Println("error copying file:", dstPath)
		return nil
	}

	content, err := os.ReadFile(dstPath)
	if err != nil {
		fmt.Println("error reading file:", dstPath)
		return nil
	}

	hash := sha256.New()
	hash.Write(content)

	fmt.Println(hex.EncodeToString(hash.Sum(nil)))

	return nil
}

func Add(args []string) {
	fmt.Println("Add:", args)

	if len(args) > 0 {
		switch args[0] {
		case "help":
			AddHelp()
			os.Exit(0)
		default:
			err := addFile(args[0])
			if err != nil {
				os.Exit(1)
			}
		}
	} else {
		AddHelp()
		os.Exit(1)
	}
}
