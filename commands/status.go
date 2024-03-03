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

	if config.Verbose {
		fmt.Printf(theme.ColorPurple+"%v(%v)"+theme.ColorReset+"\n", task.Timestamp, time.Now().UTC().Sub(task.Timestamp))
	}

	jsonData, err = os.ReadFile(config.RctfFilesName)
	if err != nil {
		fmt.Println("no files added yet... exiting")
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
	}
}
