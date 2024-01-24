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

	fmt.Printf("name: %s\n", task.Name)
	fmt.Printf("desc: %s\n", task.Description)
	fmt.Printf("cat: %s\n", task.Category)

	fmt.Printf("start: %v, elapsed: %v\n", task.Timestamp, time.Now().UTC().Sub(task.Timestamp))

	if len(task.Ip) > 0 {
		fmt.Printf("remote: %s:%v\n", task.Ip, task.Port)
	}

	if len(task.Url) > 0 {
		fmt.Printf("url: %s\n", task.Url)
	}
}
