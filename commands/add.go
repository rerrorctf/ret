package commands

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"rctf/config"
	"rctf/data"
	"rctf/theme"
	"rctf/util"
	"time"
)

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

func parseFiles(files *data.Files) {
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
}

func writeFiles(files *data.Files) {
	jsonData, err := json.MarshalIndent(files, "", "  ")
	if err != nil {
		fmt.Println("error marshalling json:", err)
		os.Exit(1)
	}

	err = os.WriteFile(config.RctfFilesName, jsonData, 0644)
	if err != nil {
		fmt.Println("error writing to file:", err)
		os.Exit(1)
	}
}

func addFile(srcPath string) {
	files := data.Files{}
	parseFiles(&files)

	_, fileName := filepath.Split(srcPath)

	fileOutput := util.RunFileCommandOnFile(srcPath)

	content, err := os.ReadFile(srcPath)
	if err != nil {
		fmt.Println("error reading file:", srcPath)
		return
	}

	md5Hash := md5.New()
	md5Hash.Write(content)
	md5HashString := hex.EncodeToString(md5Hash.Sum(nil))

	sha1Hash := sha1.New()
	sha1Hash.Write(content)
	sha1HashString := hex.EncodeToString(sha1Hash.Sum(nil))

	sha256Hash := sha256.New()
	sha256Hash.Write(content)
	sha256HashString := hex.EncodeToString(sha256Hash.Sum(nil))

	dirPath := config.FilesFolderName + "/" + sha256HashString
	dstPath := dirPath + "/" + fileName

	file := data.File{
		Filename:  fileName,
		Filepath:  dstPath,
		Size:      len(content),
		Type:      fileOutput,
		MD5:       md5HashString,
		SHA1:      sha1HashString,
		SHA256:    sha256HashString,
		Timestamp: time.Now().UTC(),
	}

	if _, err := os.Stat(dirPath); !os.IsNotExist(err) {
		fmt.Printf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": file \"%s\" with sha256 \"%s\" already added...\n",
			srcPath, sha256HashString)
		return
	}

	err = os.MkdirAll(dirPath, 0755)
	if err != nil {
		fmt.Println("error making directory:", dirPath)
		return
	}

	err = copyFile(srcPath, dstPath)
	if err != nil {
		fmt.Println("error copying file:", dstPath)
		return
	}

	fmt.Printf("📥 adding \"%s\" with sha256 \"%s\"\n", srcPath, sha256HashString)

	files.Files = append(files.Files, file)

	writeFiles(&files)

	util.ProcessFile(dstPath)
}

func AddHelp() {
	fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"add"+theme.ColorReset+" file "+theme.ColorGray+"[file file...]"+theme.ColorReset+"\n")
	fmt.Fprintf(os.Stderr, "  📥 add one or more files to the current task with rctf\n")
	os.Exit(0)
}

func Add(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			AddHelp()
			os.Exit(0)
		default:
			for _, file := range args {
				addFile(file)
			}
		}
	} else {
		AddHelp()
		os.Exit(1)
	}
}
