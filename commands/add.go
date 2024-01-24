package commands

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"rctf/config"
	"rctf/data"
	"time"
)

func AddHelp() {
	fmt.Println("rctf add help would go here...")
}

func filesAlreadyExists() bool {
	_, err := os.Stat(config.RctfFilesName)
	return !os.IsNotExist(err)
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
	fmt.Printf("adding \"%s\"...\n", srcPath)

	files := data.Files{}
	if filesAlreadyExists() {
		jsonData, err := os.ReadFile(config.RctfFilesName)
		if err != nil {
			fmt.Println("error reading:", config.RctfFilesName)
			os.Exit(1)
		}

		err = json.Unmarshal(jsonData, &files)
		if err != nil {
			fmt.Println("error unmarshalling json:", err)
			os.Exit(1)
		}
	}

	//

	_, fileName := filepath.Split(srcPath)

	dstPath := config.FilesFolderName + "/" + fileName

	err := copyFile(srcPath, dstPath)
	if err != nil {
		fmt.Println("error copying file:", dstPath)
		return nil
	}

	//

	content, err := os.ReadFile(dstPath)
	if err != nil {
		fmt.Println("error reading file:", dstPath)
		return nil
	}

	hash := sha256.New()
	hash.Write(content)

	//

	file := data.File{
		Filename:  fileName,
		Filepath:  dstPath,
		Size:      len(content),
		Type:      "todo",
		MD5:       hex.EncodeToString(hash.Sum(nil)),
		SHA1:      hex.EncodeToString(hash.Sum(nil)),
		SHA256:    hex.EncodeToString(hash.Sum(nil)),
		Timestamp: time.Now().UTC(),
	}

	jsonData, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		fmt.Println("error marshalling json:", err)
		os.Exit(1)
	}

	fmt.Printf("%s\n", jsonData)

	//

	files.Files = append(files.Files, file)

	jsonData, err = json.MarshalIndent(files, "", "  ")
	if err != nil {
		fmt.Println("error marshalling json:", err)
		os.Exit(1)
	}

	err = os.WriteFile(config.RctfFilesName, jsonData, 0644)
	if err != nil {
		fmt.Println("error writing to file:", err)
		os.Exit(1)
	}

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
			_, err := os.Stat(config.TaskName)
			if os.IsNotExist(err) {
				fmt.Printf("error: no %s found\nrun ~ $ rctf init ~ first\n", config.TaskName)
				os.Exit(1)
			}

			err = addFile(args[0])
			if err != nil {
				os.Exit(1)
			}
		}
	} else {
		AddHelp()
		os.Exit(1)
	}
}
