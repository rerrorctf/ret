package util

import (
	"log"
	"os"
	"ret/config"
	"ret/theme"
)

func EnsureDirectory(dirPath string) {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		err := os.MkdirAll(dirPath, 0755)
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
		}
	}
}

func EnsureSkeleton() {
	EnsureDirectory(config.FolderName)
	EnsureDirectory(config.FilesFolderName)
}
