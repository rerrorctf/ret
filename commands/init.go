package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"rctf/config"
	"rctf/data"
	"strconv"
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

func createRevTask(task *data.Task, scanner *bufio.Scanner) {
	fmt.Print("enter the remote ip (if this rev task has one ~ blank otherwise): ")
	scanner.Scan()
	task.Ip = scanner.Text()
	// TODO validate ip address is valid / reachable

	fmt.Print("enter the remote port (if this rev task has one ~ blank otherwise): ")
	scanner.Scan()
	port, err := strconv.Atoi(scanner.Text())
	if err != nil {
		fmt.Println("error reading port:", err)
		os.Exit(1)
	}

	// TODO validate if port is a valid port number
	task.Port = port
}

func createWebTask(task *data.Task, scanner *bufio.Scanner) {
	fmt.Print("enter the website url (can be left blank for none): ")
	scanner.Scan()
	task.Url = scanner.Text()
	// TODO validate if this is a valid url / reachable / has http/https prefix
}

func createPwnTask(task *data.Task, scanner *bufio.Scanner) {
	fmt.Print("enter the remote ip (can be left blank for no remote): ")
	scanner.Scan()
	task.Ip = scanner.Text()

	// TODO validate ip address is valid / reachable

	fmt.Print("enter the remote port (can be left blank for no remote): ")
	scanner.Scan()
	port, err := strconv.Atoi(scanner.Text())
	if err != nil {
		fmt.Println("error reading port:", err)
		os.Exit(1)
	}

	// TODO validate if port is a valid port number
	task.Port = port
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

	switch task.Category {
	case "cry":
	case "rev":
		createRevTask(&task, scanner)
	case "web":
		createWebTask(&task, scanner)
	case "pwn":
		createPwnTask(&task, scanner)
	default:
		fmt.Printf("category \"%s\" invokes no special treatment\n", task.Category)
	}

	writeTask(task)
}

func Init(args []string) {
	fmt.Println("Init:", args)

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

// should setup .rctf structure
// 	- task.json
// 		- all details
//		- timestamp,
// 	- should setup git repo
//  - for pwn it should setup go.py
//  - for rev it should setup ghidra project perhaps?
//	- it should create notes.txt file
// could potentially ping a discord bot via a webhook
