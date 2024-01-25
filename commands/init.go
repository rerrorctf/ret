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
}

func createTask(args []string) {
	task := data.Task{
		Timestamp: time.Now().UTC(),
	}

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("🚀 starting new task @ %v\n", task.Timestamp)

	if len(args) > 0 {
		fmt.Printf("task name: %s\n", args[0])
		task.Name = args[0]
	} else {
		fmt.Print("enter the task name: ")
		scanner.Scan()
		task.Name = scanner.Text()
	}

	if len(args) > 1 {
		fmt.Printf("task description: %s\n", args[1])
		task.Description = args[1]
	} else {
		fmt.Print("enter the task description: ")
		scanner.Scan()
		task.Description = scanner.Text()
	}

	if len(args) > 2 {
		fmt.Printf("task category: %s\n", args[2])
		task.Category = args[2]
	} else {
		fmt.Print("enter the category: ")
		scanner.Scan()
		task.Category = scanner.Text()
	}

	writeTask(task)
}

func Init(args []string) {
	if config.Verbose {
		fmt.Println("Init:", args)
	}

	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

			fmt.Fprintf(os.Stderr, "usage: %s init [name] [description] [category]\n", os.Args[0])

			fmt.Fprintf(os.Stderr, "  initializes the cwd for a task with rctf\n")

			fmt.Fprintf(os.Stderr, "\nsubcommands:\n")
			fmt.Fprintf(os.Stderr, "  ❓ help ~ print this message\n")

			fmt.Fprintf(os.Stderr, "\n~ 🚩 @rerrorctf 🚩 ~\n")
			fmt.Fprintf(os.Stderr, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")

			os.Exit(0)
		}
	}

	if taskAlreadyExists() {
		fmt.Printf("%s already exists\n", config.TaskName)
		os.Exit(1)
	}

	createTask(args)
}
