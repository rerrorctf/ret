package commands

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
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

func runFileCommandOnFile(path string) string {
	fileOutput := exec.Command("file", path)

	fileOutputResult, err := fileOutput.Output()
	if err != nil {
		fmt.Printf("warning: unable to get output from file on %s\n", path)
		return ""
	}

	return string(fileOutputResult[len(path)+2 : len(fileOutputResult)-1])
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
	fmt.Printf("📥 adding \"%s\"...\n", srcPath)

	files := data.Files{}
	parseFiles(&files)

	_, fileName := filepath.Split(srcPath)

	fileOutput := runFileCommandOnFile(srcPath)

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

	util.ProcessFile(&file, dstPath)

	files.Files = append(files.Files, file)

	writeFiles(&files)
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
			_, err := os.Stat(config.TaskName)
			if os.IsNotExist(err) {
				log.Fatalf("error: no %s found\nrun "+theme.ColorBlue+"init"+theme.ColorReset+" first\n", config.TaskName)
			}

			for _, file := range args {
				addFile(file)
			}
		}
	} else {
		AddHelp()
		os.Exit(1)
	}
}
