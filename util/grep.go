package util

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"ret/theme"
)

func Grep(path string, pattern string) {
	file, err := os.Open(path)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": opening file %v\n", path)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if match, _ := regexp.MatchString(pattern, line); match {
			fmt.Println(line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}
