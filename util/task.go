package util

import (
	"encoding/json"
	"log"
	"os"
	"ret/config"
	"ret/data"
	"ret/theme"
)

func GetCurrentTask() data.Task {
	var task data.Task
	task.Ip = "127.0.0.1"
	task.Port = 9001

	jsonData, err := os.ReadFile(config.TaskFileName)
	if err != nil {
		return task
	}

	err = json.Unmarshal(jsonData, &task)
	if err != nil {
		return task
	}

	return task
}

func SetCurrentTask(task *data.Task) {
	jsonData, err := json.MarshalIndent(task, "", "  ")
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	err = os.WriteFile(config.TaskFileName, jsonData, 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}

func GetCurrentTaskName() string {
	task := GetCurrentTask()
	return task.Name
}

func SetCurrentTaskName(name string) {
	task := GetCurrentTask()
	task.Name = name
	SetCurrentTask(&task)
}

func GetCurrentTaskCategory() string {
	task := GetCurrentTask()
	return task.Category
}

func SetCurrentTaskCategory(category string) {
	task := GetCurrentTask()
	task.Category = category
	SetCurrentTask(&task)
}

func GetCurrentTaskDescription() string {
	task := GetCurrentTask()
	return task.Description
}

func SetCurrentTaskDescription(description string) {
	task := GetCurrentTask()
	task.Description = description
	SetCurrentTask(&task)
}

func GetCurrentTaskFlag() string {
	task := GetCurrentTask()
	return task.Flag
}

func SetCurrentTaskFlag(flag string) {
	task := GetCurrentTask()
	task.Flag = flag
	SetCurrentTask(&task)
}

func GetCurrentTaskIp() string {
	task := GetCurrentTask()
	return task.Ip
}

func SetCurrentTaskIp(ip string) {
	task := GetCurrentTask()
	task.Ip = ip
	SetCurrentTask(&task)
}

func GetCurrentTaskPort() int {
	task := GetCurrentTask()
	return task.Port
}

func SetCurrentTaskPort(port int) {
	task := GetCurrentTask()
	task.Port = port
	SetCurrentTask(&task)
}

func GetCurrentTaskEvent() string {
	task := GetCurrentTask()
	return task.Event
}

func SetCurrentTaskEvent(event string) {
	task := GetCurrentTask()
	task.Event = event
	SetCurrentTask(&task)
}
