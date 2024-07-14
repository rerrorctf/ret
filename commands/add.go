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

func AddHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "add" + theme.ColorReset + " file1 " + theme.ColorGray + "[file2 file3...]" + theme.ColorReset + "\n")
	fmt.Printf("  📥 add one or more files to the current task with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/add.go" + theme.ColorReset + "\n")
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
		AddHelp()
		return
	}

	for _, file := range args {
		addFile(file)
	}
}
