package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"ret/config"
	"ret/theme"
	"strings"
	"time"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "ctftime",
		Emoji: "🚩",
		Func:  CtfTime,
		Help:  CtfTimeHelp,
		Arguments: []Argument{
			{
				Name:     "url",
				Optional: true,
				List:     false,
			},
		},
		SeeAlso: []string{"writeup"}})
}

func CtfTimeHelp() string {
	return "set the current ctftime url with ret\n\n" +
		"the ctftime url is stored in " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + " using the " + theme.ColorYellow + "`\"ctftimeurl\"`" + theme.ColorReset + " field\n\n" +
		"the ctftime url will be used to aid in the generation of writeups with the " + theme.ColorGreen + "`writeup`" + theme.ColorReset + " command\n"
}

func CtfTime(args []string) {
	if len(args) > 0 {
		fmt.Printf(theme.ColorGray+"old ctftime url: "+theme.ColorRed+"%v"+theme.ColorReset+"\n", config.CtfTimeUrl)

		config.CtfTimeUrl = strings.Trim(args[0], "/")

		config.WriteUserConfig()

		fmt.Printf(theme.ColorGray+"new ctftime url: "+theme.ColorGreen+"%v"+theme.ColorReset+"\n", config.CtfTimeUrl)
		return
	}

	fmt.Printf(theme.ColorGray+"url: "+theme.ColorReset+"%v"+theme.ColorReset+"\n", config.CtfTimeUrl)

	if !strings.Contains(config.CtfTimeUrl, "ctftime.org") {
		return
	}

	splits := strings.Split(config.CtfTimeUrl, "/")
	eventId := splits[len(splits)-1]

	url := fmt.Sprintf("https://ctftime.org/api/v1/events/%s/", eventId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	title := result["title"]
	fmt.Printf(theme.ColorGray+"title: "+theme.ColorBlue+"%s"+theme.ColorReset+"\n", title)

	now := time.Now()

	start := fmt.Sprintf("%s", result["start"])
	startTime, err := time.Parse(time.RFC3339, start)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	finish := fmt.Sprintf("%s", result["finish"])
	finishTime, err := time.Parse(time.RFC3339, finish)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	fmt.Printf(theme.ColorGray+"start: "+theme.ColorGreen+"%v "+theme.ColorGray+"finish: "+theme.ColorRed+"%v"+theme.ColorReset+"\n", startTime, finishTime)

	started := startTime.Before(now)
	finished := finishTime.Before(now)
	ongoing := started && !finished

	if ongoing {
		fmt.Printf(theme.ColorGray+"time remaining: "+theme.ColorReset+"%v\n", finishTime.Sub(now))
	} else if finished {
		fmt.Printf(theme.ColorGray+"time since finish: "+theme.ColorReset+"%v\n", finishTime.Sub(now))
	} else {
		fmt.Printf(theme.ColorGray+"time to start: "+theme.ColorReset+"%v\n", startTime.Sub(now))
		fmt.Printf(theme.ColorGray+"time to finish: "+theme.ColorReset+"%v\n", finishTime.Sub(now))
	}
}
