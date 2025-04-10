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

type CTFTimeInfo struct {
	Title  string
	Start  time.Time
	Finish time.Time
}

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
		SeeAlso: []string{"rmctf", "writeup"}})
}

func CtfTimeHelp() string {
	return "adds a ctftime url with ret\n\n" +
		"the ctftime urls are stored in " + theme.ColorCyan + "`~/.config/ret`" + theme.ColorReset + " using the " + theme.ColorYellow + "`\"ctftimeurls\"`" + theme.ColorReset + " field\n\n" +
		"the command will use the ctftime.org api to fetch details about all the currently set ctftime urls and then display them\n\n" +
		"the ctf's title, start time and finish time will be displayed along with an indication of the time to the start or finish depending on the context\n\n" +
		"for more details please see https://ctftime.org/api/\n\n" +
		"the ctftime urls will be used to aid in the generation of writeups with the " + theme.ColorGreen + "`writeup`" + theme.ColorReset + " command\n\n"
}

func ctftimeSpinner() {
	emojis := []string{
		"🕛", "⏳", "🕧", "🕐", "⏰", "🕞", "⏲️", "🚩",
	}

	for {
		for _, e := range emojis {
			fmt.Printf("\r%s", e)
			time.Sleep(200 * time.Millisecond)
		}
	}
}

func fetchInfo(ctfTimeUrl string, info *CTFTimeInfo) {
	splits := strings.Split(ctfTimeUrl, "/")
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

	info.Title = fmt.Sprintf("%s", result["title"])

	start := fmt.Sprintf("%s", result["start"])
	info.Start, err = time.Parse(time.RFC3339, start)

	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}

	finish := fmt.Sprintf("%s", result["finish"])
	info.Finish, err = time.Parse(time.RFC3339, finish)

	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
	}
}

func showInfo(info *CTFTimeInfo) {
	now := time.Now()

	started := info.Start.Before(now)
	finished := info.Finish.Before(now)
	ongoing := started && !finished

	fmt.Printf(theme.ColorGray+"title:  "+theme.ColorBlue+"%s"+theme.ColorReset+" ", info.Title)

	if ongoing {
		fmt.Printf(theme.ColorGray+"time remaining: "+theme.ColorReset+"%v\n", info.Finish.Sub(now))
	} else if finished {
		fmt.Printf(theme.ColorGray+"time since finish: "+theme.ColorReset+"%v\n", info.Finish.Sub(now))
	} else {
		delta := info.Start.Sub(now)

		hours := int(delta.Hours())
		mins := int(delta.Minutes())
		seconds := int(delta.Seconds())

		if hours > 0 {
			fmt.Printf(theme.ColorGray+"starts in "+theme.ColorPurple+"~%v"+theme.ColorGray+" hours\n", hours)
		} else if mins > 0 {
			fmt.Printf(theme.ColorGray+"starts in "+theme.ColorPurple+"~%v"+theme.ColorGray+" mins\n", mins)
		} else {
			fmt.Printf(theme.ColorGray+"starts in "+theme.ColorPurple+"~%v"+theme.ColorGray+" seconds\n", seconds)
		}
	}

	fmt.Printf(theme.ColorGray+"start:  "+theme.ColorGreen+"%v"+theme.ColorReset+"\n", info.Start.Local())
	fmt.Printf(theme.ColorGray+"finish: "+theme.ColorRed+"%v"+theme.ColorReset+"\n", info.Finish.Local())
}

func CtfTime(args []string) {
	if len(args) > 0 {
		newCtfTimeUrl := strings.Trim(args[0], "/")

		for _, ctfTimeUrl := range config.CtfTimeUrls {
			if newCtfTimeUrl == ctfTimeUrl {
				log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": a ctf with the url %v has already been registered\n", newCtfTimeUrl)
				return
			}
		}

		config.CtfTimeUrls = append(config.CtfTimeUrls, newCtfTimeUrl)

		config.WriteUserConfig()

		fmt.Printf(theme.ColorGray+"new ctftime url: "+theme.ColorGreen+"%v"+theme.ColorReset+"\n", newCtfTimeUrl)
		return
	}

	if len(config.CtfTimeUrls) == 0 {
		return
	}

	go ctftimeSpinner()

	infos := make([]CTFTimeInfo, len(config.CtfTimeUrls))

	for idx, ctfTimeUrl := range config.CtfTimeUrls {
		if strings.Contains(ctfTimeUrl, "ctftime.org") {
			fetchInfo(ctfTimeUrl, &infos[idx])
		}
	}

	fmt.Printf("\r")

	for idx, ctfTimeUrl := range config.CtfTimeUrls {
		fmt.Printf(theme.ColorGray+"url:    "+theme.ColorCyan+theme.StartUnderline+"%v"+theme.ColorReset+theme.StopUnderline+"\n", ctfTimeUrl)

		if strings.Contains(ctfTimeUrl, "ctftime.org") {
			showInfo(&infos[idx])
			if idx+1 < len(config.CtfTimeUrls) {
				fmt.Printf("\n")
			}
		}
	}
}
