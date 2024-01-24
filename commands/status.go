package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"rctf/config"
	"rctf/data"
	"time"
)

func StatusHelp() {
	fmt.Println("rctf status help would go here...")
}

func Status(args []string) {
	fmt.Println("Status:", args)

	if len(args) > 0 {
		switch args[0] {
		case "help":
			StatusHelp()
			os.Exit(0)
		}
	}

	jsonData, err := os.ReadFile(config.TaskName)
	if err != nil {
		fmt.Printf("error reading %s %v\n", config.TaskName, err)
		os.Exit(1)
	}

	var task data.Task

	err = json.Unmarshal(jsonData, &task)
	if err != nil {
		fmt.Println("error unmarshalling json:", err)
		os.Exit(1)
	}

	fmt.Printf("%s (%s) ~ %v(%v)\n", task.Name, task.Category,
		task.Timestamp, time.Now().UTC().Sub(task.Timestamp))

	if len(task.Description) > 0 {
		fmt.Printf("desc: %s\n", task.Description)
	}

	if len(task.Ip) > 0 {
		fmt.Printf("    remote: %s:%v\n", task.Ip, task.Port)
	}

	if len(task.Url) > 0 {
		fmt.Printf("    url: %s\n", task.Url)
	}

	jsonData, err = os.ReadFile(config.RctfFilesName)
	if err != nil {
		os.Exit(1)
	}

	fmt.Println("files:")

	var files data.Files

	err = json.Unmarshal(jsonData, &files)
	if err != nil {
		fmt.Println("error unmarshalling json:", err)
		os.Exit(1)
	}

	for idx, file := range files.Files {
		fmt.Printf("[%v] %s (%v bytes)\n", idx, file.Filename, file.Size)
		fmt.Printf("     type:   %s...\n", file.Type[:25])
		fmt.Printf("     md5:    %s\n", file.MD5)
		fmt.Printf("     sha1:   %s\n", file.SHA1)
		fmt.Printf("     sha256: %s\n", file.SHA256)
		if len(file.Comment) > 0 {
			fmt.Printf("     comment: %s\n", file.Comment)
		}
		fmt.Printf("%v(%v)\n", file.Timestamp, time.Now().UTC().Sub(file.Timestamp))
	}
}
