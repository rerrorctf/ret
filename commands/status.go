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
	if config.Verbose {
		fmt.Println("Status:", args)
	}

	if len(args) > 0 {
		switch args[0] {
		case "help":
			StatusHelp()
			os.Exit(0)
		}
	}

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

	fmt.Printf("%s (%s) ~ %v(%v)\n", task.Name, task.Category,
		task.Timestamp, time.Now().UTC().Sub(task.Timestamp))

	if len(task.Description) > 0 {
		fmt.Printf("desc: %s\n", task.Description)
	}

	jsonData, err = os.ReadFile(config.RctfFilesName)
	if err != nil {
		os.Exit(1)
	}

	fmt.Println("\nfiles:")
	fmt.Println("########################################################")

	var files data.Files

	err = json.Unmarshal(jsonData, &files)
	if err != nil {
		fmt.Println("error unmarshalling json:", err)
		os.Exit(1)
	}

	for idx, file := range files.Files {
		fmt.Printf("[%v] %s (%v bytes)\n", idx, file.Filename, file.Size)

		if len(file.Type) < 60 {
			fmt.Printf("     type:   %s\n", file.Type)
		} else {
			fmt.Printf("     type:   %s...\n", file.Type[:60])
		}

		fmt.Printf("     md5:    %s\n", file.MD5)
		fmt.Printf("     sha1:   %s\n", file.SHA1)
		fmt.Printf("     sha256: %s\n", file.SHA256)

		if len(file.Comment) > 0 {
			fmt.Printf("     comment: %s\n", file.Comment)
		}
		fmt.Printf("%v(%v)\n", file.Timestamp, time.Now().UTC().Sub(file.Timestamp))
		fmt.Println("########################################################")
	}
}
