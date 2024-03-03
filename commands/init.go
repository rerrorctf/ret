package commands

import (
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

	fmt.Printf("🚀 starting new task @ %v\n", task.Timestamp)

	if len(args) > 0 {
		fmt.Printf(theme.ColorGray+"task flag format: "+theme.ColorYellow+"%s"+theme.ColorReset+"\n", args[0])
		task.FlagFormat = args[0]
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
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"init"+theme.ColorGray+" [flag-format]"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  🚀 initializes the cwd for a task with rctf\n")
			os.Exit(0)
		}
	}

	if taskAlreadyExists() {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %s already exists\n", config.TaskName)
	}

	createTask(args)
}
