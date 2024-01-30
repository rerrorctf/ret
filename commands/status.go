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

func Status(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"status"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  👀 displays the status for the current task with rctf\n")
			os.Exit(0)
		}
	}

	jsonData, err := os.ReadFile(config.TaskName)
	if err != nil {
		log.Fatalln("💥 "+theme.ColorRed+"error"+theme.ColorReset+": reading", err)
	}

	var task data.Task

	err = json.Unmarshal(jsonData, &task)
	if err != nil {
		log.Fatalln("💥 "+theme.ColorRed+"error"+theme.ColorReset+" unmarshalling json:", err)
	}

	fmt.Printf(theme.ColorGray+"task: "+theme.ColorReset+"%s "+theme.ColorGray, task.Name)

	fmt.Printf("("+theme.ColorPurple+"%s"+theme.ColorGray+") "+theme.ColorReset, task.Category)

	if config.Verbose {
		fmt.Printf(theme.ColorPurple+"%v(%v)"+theme.ColorReset+"\n", task.Timestamp, time.Now().UTC().Sub(task.Timestamp))
	} else {
		fmt.Printf("\n")
	}

	if len(task.Description) > 0 {
		fmt.Printf("\"%s\"\n", task.Description)
	}

	jsonData, err = os.ReadFile(config.RctfFilesName)
	if err != nil {
		if config.Verbose {
			fmt.Println("no files added yet... exiting")
		}
		os.Exit(1)
	}

	var files data.Files

	err = json.Unmarshal(jsonData, &files)
	if err != nil {
		log.Fatalln("💥 "+theme.ColorRed+"error"+theme.ColorReset+": unmarshalling json", err)
	}

	for idx, file := range files.Files {
		fmt.Printf(theme.ColorGray+"["+theme.ColorBlue+"%v"+theme.ColorGray+"]"+theme.ColorReset, idx)

		fmt.Printf(theme.ColorGreen+" %s ", file.Filename)

		fmt.Printf(theme.ColorGray+"("+theme.ColorCyan+"%vB"+theme.ColorGray+"/"+theme.ColorRed+"%vK"+theme.ColorGray+"/"+theme.ColorYellow+"%vM"+theme.ColorGray+"/"+theme.ColorBlue+"%vG"+theme.ColorGray+")"+theme.ColorReset+" 👀\n",
			file.Size, file.Size/1024, file.Size/1024/1024, file.Size/1024/1024/1024)

		if len(file.Type) < 60 {
			fmt.Printf(theme.ColorGray+"  type:   "+theme.ColorReset+"%s\n", file.Type)
		} else {
			fmt.Printf(theme.ColorGray+"  type:   "+theme.ColorReset+"%s...\n", file.Type[:60])
		}

		if config.Verbose {
			fmt.Printf(theme.ColorGray+"  md5:    "+theme.ColorReset+"%s\n", file.MD5)
			fmt.Printf(theme.ColorGray+"  sha1:   "+theme.ColorReset+"%s\n", file.SHA1)
			fmt.Printf(theme.ColorGray+"  sha256: "+theme.ColorReset+"%s\n", file.SHA256)
		} else {
			fmt.Printf(theme.ColorGray+"  sha256: "+theme.ColorReset+"%s\n", file.SHA256)
		}

		if len(file.Comment) > 0 {
			fmt.Printf("  comment: %s\n", file.Comment)
		}

		if config.Verbose {
			fmt.Printf("  %v(%v)\n", file.Timestamp, time.Now().UTC().Sub(file.Timestamp))
		}

		logFilePath := config.FilesFolderName + "/" + file.SHA256 + "/rctflog.txt"
		logFile, err := os.ReadFile(logFilePath)
		if err != nil {
			log.Fatalln("💥 "+theme.ColorRed+"error"+theme.ColorReset+": reading log file", err)
		}

		fmt.Printf(theme.ColorGray+" => %s"+theme.ColorReset+"\n%s\n", logFilePath, logFile)
	}
}
