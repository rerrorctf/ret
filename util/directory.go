package util

import (
	"fmt"
	"os"
	"rctf/config"
)

func EnsureDirectory(dirPath string) {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		if config.Verbose {
			fmt.Println("mkdir", dirPath)
		}
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			fmt.Println("error creating directory:", err)
			os.Exit(1)
		}
	}
}

func EnsureSkeleton() {
	EnsureDirectory(config.FolderName)
	EnsureDirectory(config.FilesFolderName)
}