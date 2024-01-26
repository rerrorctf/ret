package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"rctf/config"
	"rctf/data"
	"rctf/theme"
	"time"
)

func taskAlreadyExists() bool {
	_, err := os.Stat(config.TaskName)
	return !os.IsNotExist(err)
}

func writeTask(task data.Task) {
	jsonData, err := json.MarshalIndent(task, "", "  ")
	if err != nil {
		log.Fatalln("error marshaling json:", err)
	}

	err = os.WriteFile(config.TaskName, jsonData, 0644)
	if err != nil {
		log.Fatalln("error writing to file:", err)
	}
}

func createTask(args []string) {
	task := data.Task{
		Timestamp: time.Now().UTC(),
	}

	scanner := bufio.NewScanner(os.Stdin)

	fmt.Printf("🚀 starting new task @ %v\n", task.Timestamp)

	if len(args) > 0 {
		fmt.Printf(theme.ColorGray+"task name: "+theme.ColorYellow+"%s"+theme.ColorReset+"\n", args[0])
		task.Name = args[0]
	} else {
		fmt.Print(theme.ColorGray + "enter the task name: " + theme.ColorReset)
		scanner.Scan()
		task.Name = scanner.Text()
	}

	if len(args) > 1 {
		fmt.Printf(theme.ColorGray+"task description: "+theme.ColorYellow+"%s"+theme.ColorReset+"\n", args[1])
		task.Description = args[1]
	} else {
		fmt.Print(theme.ColorGray + "enter the task description: " + theme.ColorReset)
		scanner.Scan()
		task.Description = scanner.Text()
	}

	if len(args) > 2 {
		fmt.Printf(theme.ColorGray+"task category: "+theme.ColorYellow+"%s"+theme.ColorReset+"\n", args[2])
		task.Category = args[2]
	} else {
		fmt.Print(theme.ColorGray + "enter the category: " + theme.ColorReset)
		scanner.Scan()
		task.Category = scanner.Text()
	}

	if len(args) > 3 {
		fmt.Printf(theme.ColorGray+"task flag format: "+theme.ColorYellow+"%s"+theme.ColorReset+"\n", args[3])
		task.FlagFormat = args[3]
	} else {
		fmt.Print(theme.ColorGray + "enter the flag format (as a regular expression): " + theme.ColorReset)
		scanner.Scan()
		task.FlagFormat = scanner.Text()
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
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"init"+theme.ColorGray+" [name] [description] [category] [flag-format]"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  🚀 initializes the cwd for a task with rctf\n")
			os.Exit(0)
		}
	}

	if taskAlreadyExists() {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %s already exists\n", config.TaskName)
	}

	createTask(args)
}
