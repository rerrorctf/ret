package commands

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"ret/config"
	"ret/data"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "add",
		Emoji: "📥",
		Func:  Add,
		Help:  AddHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/add.go",
		Arguments: []Argument{
			{
				Name:     "file",
				Optional: false,
				List:     true,
			},
		}})
}

func AddHelp() string {
	return "add one or more files to the current task with ret\n\n" +
		"performs the following steps:\n" +
		"1. analyze each file to determine if it is an elf or not by examing the file's magic bytes\n" +
		"2. generate a sha-2-256 hash for each file\n" +
		"3. added files are copied into the hidden directory `.ret/files` inside a subfolder that is named using the sha-2-256 hex digest of the file content\n" +
		"4. save metadata about the files, specifically their length, location and file type (i.e. elf or not), in the files json file in the hidden `.ret` directory\n" +
		"5. uses strings, with widths of 8, 16 and 32 bits per character, in combination with grep to search for flags according to the flag format\n" +
		"6. uses yara to search for constants associated with cryptography. this is equivilent to running the `crypto` command on the files\n\n" +
		"added files are subject to processing by other commands that operate on the set of added files\n\n" +
		"adding a file does not prevent changes from occuring to the source file nor does it detect them for you, like a version control system would\n\n" +
		"you can track several version of a file by adding each of them remembering that they are addressed according to the hash of their content\n\n" +
		"you can restore a specific version of a file by copying it from the subdirectory in which a copy of it was made when the file was added\n"
}

func grep2Win(path string, flags string) {
	stringsCmd := exec.Command("strings", flags, path)
	var stringsOutput bytes.Buffer
	stringsCmd.Stdout = &stringsOutput
	_ = stringsCmd.Run()

	grepCmd := exec.Command("grep", "-Eoi", config.FlagFormat)
	grepCmd.Stdin = &stringsOutput
	var grepOutput bytes.Buffer
	grepCmd.Stdout = &grepOutput
	if err := grepCmd.Run(); err != nil {
		return
	}

	scanner := bufio.NewScanner(&grepOutput)
	for scanner.Scan() {
		fmt.Printf(theme.ColorPurple+"[grep2win]"+theme.ColorReset+": %s\n", scanner.Text())
	}
}

func parseFiles(files *data.Files) {
	if util.FileExists(config.RetFilesNames) {
		jsonData, err := os.ReadFile(config.RetFilesNames)
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
		}

		err = json.Unmarshal(jsonData, &files)
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
		}
	}
}

func writeFiles(files *data.Files) {
	jsonData, err := json.MarshalIndent(files, "", "  ")
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	err = os.WriteFile(config.RetFilesNames, jsonData, 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}

func addFile(srcPath string) {
	files := data.Files{}
	parseFiles(&files)

	_, fileName := filepath.Split(srcPath)

	content, err := os.ReadFile(srcPath)
	if err != nil {
		fmt.Println("💥 "+theme.ColorRed+"error"+theme.ColorReset+": reading file:", srcPath)
		return
	}

	fileType := data.FILE_TYPE_UNKNOWN

	for magicType, magic := range data.FileMagics {
		match := true
		if len(content) < len(magic) {
			continue
		}

		for j := range magic {
			if content[j] != magic[j] {
				match = false
				break
			}
		}

		if !match {
			continue
		}

		fileType = magicType
		break
	}

	sha256Hash := sha256.New()
	sha256Hash.Write(content)
	sha256HashString := hex.EncodeToString(sha256Hash.Sum(nil))

	dirPath := config.FilesFolderName + "/" + sha256HashString
	dstPath := dirPath + "/" + fileName

	file := data.File{
		Filename: fileName,
		Filepath: dstPath,
		Size:     len(content),
		FileType: fileType,
		SHA256:   sha256HashString,
	}

	if _, err := os.Stat(dirPath); !os.IsNotExist(err) {
		fmt.Printf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": file \"%s\" with sha256 \"%s\" already added...\n",
			srcPath, sha256HashString)
		return
	}

	err = os.MkdirAll(dirPath, 0755)
	if err != nil {
		fmt.Println("💥 "+theme.ColorRed+"error"+theme.ColorReset+": making directory:", dirPath)
		return
	}

	err = util.CopyFile(srcPath, dstPath)
	if err != nil {
		fmt.Println("💥 "+theme.ColorRed+"error"+theme.ColorReset+": copying file:", dstPath)
		return
	}

	fmt.Printf("📥 adding \"%s\" %s\n", srcPath, sha256HashString)

	files.Files = append(files.Files, file)

	writeFiles(&files)

	grep2Win(dstPath, "")
	grep2Win(dstPath, "-el")
	grep2Win(dstPath, "-eL")

	var buffer bytes.Buffer
	util.CryptoWithYara(dstPath, &buffer)

	scanner := bufio.NewScanner(&buffer)
	for i := 0; i < 4; i++ {
		if scanner.Scan() {
			fmt.Printf(theme.ColorPurple+"🚀 %s"+theme.ColorReset+"\n", scanner.Text())
		}
	}
	if scanner.Scan() {
		fmt.Printf(theme.ColorGray + "🚀 one or more lines hidden" + theme.ColorReset + "\n")
	}
}

func Add(args []string) {
	if len(args) == 0 {
		fmt.Println("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": excepted 1 or more arguments")
		return
	}

	for _, file := range args {
		addFile(file)
	}
}
