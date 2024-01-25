package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"rctf/config"
	"rctf/data"
	"time"
)

func InitHelp() {
	fmt.Println("rctf init help would go here...")
}

func taskAlreadyExists() bool {
	_, err := os.Stat(config.TaskName)
	return !os.IsNotExist(err)
}

func writeTask(task data.Task) {
	jsonData, err := json.MarshalIndent(task, "", "  ")
	if err != nil {
		fmt.Println("error marshaling json:", err)
		os.Exit(1)
	}

	err = os.WriteFile(config.TaskName, jsonData, 0644)
	if err != nil {
		fmt.Println("error writing to file:", err)
		os.Exit(1)
	}

	fmt.Println("data written to task.json")
}

func createTask() {
	task := data.Task{
		Timestamp: time.Now().UTC(),
	}

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("starting new task @ %v\n", task.Timestamp)

	fmt.Print("enter the task name: ")
	scanner.Scan()
	task.Name = scanner.Text()

	fmt.Print("enter the task description (for reference can be left blank for none): ")
	scanner.Scan()
	task.Category = scanner.Text()

	fmt.Print("enter the category (cry/rev/pwn/web/misc): ")
	scanner.Scan()
	task.Category = scanner.Text()

	writeTask(task)
}

func Init(args []string) {
	if config.Verbose {
		fmt.Println("Init:", args)
	}

	if len(args) > 0 {
		switch args[0] {
		case "help":
			InitHelp()
			os.Exit(0)
		}
	}

	if taskAlreadyExists() {
		fmt.Printf("%s already exists\n", config.TaskName)
		os.Exit(1)
	}

	createTask()
}
