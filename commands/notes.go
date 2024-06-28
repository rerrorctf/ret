package commands

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"ret/config"
	"ret/data"
	"ret/theme"
	"ret/util"
	"strings"
	"time"
)

func displayNotes() {
	jsonData, err := os.ReadFile(config.NotesFileName)
	if err != nil {
		return
	}

	var notes data.Notes
	err = json.Unmarshal(jsonData, &notes)
	if err != nil {
		return
	}

	for _, note := range notes.Notes {
		fmt.Printf("✏️  "+theme.ColorPurple+"%v\n"+theme.ColorReset+"%s\n", note.Timestamp, note.Note)
	}
}

func addNote(note string) {
	notes := data.Notes{}

	if util.FileExists(config.NotesFileName) {
		jsonData, err := os.ReadFile(config.NotesFileName)
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
		}

		err = json.Unmarshal(jsonData, &notes)
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
		}
	}

	newNote := data.Note{
		Note:      note,
		Timestamp: time.Now(),
	}

	notes.Notes = append(notes.Notes, newNote)

	jsonData, err := json.MarshalIndent(notes, "", "  ")
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	err = os.WriteFile(config.NotesFileName, jsonData, 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}

func notesHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "notes" + theme.ColorGray + " message" + theme.ColorReset + "\n")
	fmt.Printf("  ✏️  take notes with ret\n")
	fmt.Printf("     " + theme.ColorGray + "use - to read from stdin" + theme.ColorReset + "\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/notes.go" + theme.ColorReset + "\n")
}

func Notes(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			notesHelp()
			return
		}
	} else {
		displayNotes()
		return
	}

	util.EnsureSkeleton()

	if strings.Compare("-", args[0]) == 0 {
		var buffer bytes.Buffer
		_, err := io.Copy(&buffer, os.Stdin)
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
		}

		if len(args) > 1 {
			addNote(buffer.String() + "\n" + strings.Join(args[1:], " "))
		} else {
			addNote(buffer.String())
		}

		return
	} else {
		addNote(strings.Join(args, " "))
	}
}
