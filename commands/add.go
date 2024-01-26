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
	"os/exec"
	"path/filepath"
	"rctf/config"
	"rctf/data"
	"rctf/theme"
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

func ensureFileNotAdded(file *data.File, files *data.Files) bool {
	for _, f := range files.Files {
		if file.SHA256 == f.SHA256 {
			fmt.Printf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": file \"%s\" with sha256 \"%s\" already added...\n",
				f.Filename, f.SHA256)
			return false
		}
	}

	return true
}

func grep2Win(file *data.File, path string) {
	jsonData, err := os.ReadFile(config.TaskName)
	if err != nil {
		fmt.Println("error reading:", err)
		os.Exit(1)
	}

	var task data.Task

	err = json.Unmarshal(jsonData, &task)
	if err != nil {
		fmt.Println("error unmarshalling json:", err)
		os.Exit(1)
	}

	grep2win := exec.Command("grep", "-aEoi", task.FlagFormat, path)
	grep2winOutput, err := grep2win.Output()
	if err == nil {
		fmt.Printf(theme.ColorPurple+"[grep2win]"+theme.ColorReset+": %s", grep2winOutput)
	}
}

func processFile(file *data.File, path string) {
	grep2Win(file, path)
}

func addFile(srcPath string) error {
	fmt.Printf("📥 adding \"%s\"...\n", srcPath)

	files := data.Files{}
	parseFiles(&files)

	_, fileName := filepath.Split(srcPath)

	dstPath := config.FilesFolderName + "/" + fileName

	fileOutput := runFileCommandOnFile(srcPath)

	content, err := os.ReadFile(srcPath)
	if err != nil {
		fmt.Println("error reading file:", srcPath)
		return nil
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

	if !ensureFileNotAdded(&file, &files) {
		return nil
	}

	err = copyFile(srcPath, dstPath)
	if err != nil {
		fmt.Println("error copying file:", dstPath)
		return nil
	}

	processFile(&file, dstPath)

	files.Files = append(files.Files, file)

	writeFiles(&files)

	return nil
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
				fmt.Printf("error: no %s found\nrun "+theme.ColorBlue+"init"+theme.ColorReset+" first\n", config.TaskName)
				os.Exit(1)
			}

			for _, file := range args {
				err = addFile(file)
			}

			if err != nil {
				os.Exit(1)
			}
		}
	} else {
		AddHelp()
		os.Exit(1)
	}
}
