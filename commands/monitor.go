package commands

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"rctf/config"
	"rctf/theme"
	"rctf/util"
	"strconv"
	"syscall"
	"time"
)

var (
	montitorScanInterval = 60 * time.Second
)

func waitForTerm(sigChan <-chan os.Signal) {
	<-sigChan
	fmt.Println("\r\n👋")

	if config.MonitorWebhook != "" {
		hook := exec.Command("curl", "-H", "Content-type: application/json", "-d", `{"content": "stopped monitoring"}`,
			config.MonitorWebhook)
		hook.Run()
	}

	os.Exit(0)
}

func monitorServer(serverAddress string) {
	connected := false
	for {
		_, err := net.Dial("tcp", serverAddress)
		if err != nil {
			if connected {
				fromUpToDown(serverAddress)
				connected = false
			}

		} else {
			if !connected {
				fromDownToUp(serverAddress)
				connected = true
			}
		}

		time.Sleep(montitorScanInterval)
	}
}

func monitorSpinner() {
	interval := 750 * time.Millisecond

	for {
		fmt.Printf("\r" + theme.ColorGray + "[" + theme.ColorPurple + "⠋" + theme.ColorGray + "]" + theme.ColorReset + " 📡 📧        🌐")
		time.Sleep(interval)

		fmt.Printf("\r" + theme.ColorGray + "[" + theme.ColorPurple + "⠙" + theme.ColorGray + "]" + theme.ColorReset + " 📡  📧       🌐")

		time.Sleep(interval)

		fmt.Printf("\r" + theme.ColorGray + "[" + theme.ColorPurple + "⠹" + theme.ColorGray + "]" + theme.ColorReset + " 📡   📧      🌐")

		time.Sleep(interval)

		fmt.Printf("\r" + theme.ColorGray + "[" + theme.ColorPurple + "⠸" + theme.ColorGray + "]" + theme.ColorReset + " 📡    📧     🌐")
		time.Sleep(interval)

		fmt.Printf("\r" + theme.ColorGray + "[" + theme.ColorPurple + "⠼" + theme.ColorGray + "]" + theme.ColorReset + " 📡     📧    🌐")
		time.Sleep(interval)

		fmt.Printf("\r" + theme.ColorGray + "[" + theme.ColorPurple + "⠴" + theme.ColorGray + "]" + theme.ColorReset + " 📡      📧   🌐")
		time.Sleep(interval)

		fmt.Printf("\r" + theme.ColorGray + "[" + theme.ColorPurple + "⠦" + theme.ColorGray + "]" + theme.ColorReset + " 📡       📧  🌐")
		time.Sleep(interval)

		fmt.Printf("\r" + theme.ColorGray + "[" + theme.ColorPurple + "⠧" + theme.ColorGray + "]" + theme.ColorReset + " 📡        📧 🌐")
		time.Sleep(interval)
	}
}

func fromDownToUp(serverAddress string) {
	fmt.Printf(theme.ColorGreen+"\r[conn]"+theme.ColorReset+" ⤴️: %v\n", time.Now().UTC())

	if config.MonitorWebhook != "" {
		msg := fmt.Sprintf(`{"content": "[conn] ⤴️: %s"}`, serverAddress)
		hook := exec.Command("curl", "-H", "Content-type: application/json", "-d", msg,
			config.MonitorWebhook)
		hook.Run()
	}
}

func fromUpToDown(serverAddress string) {
	fmt.Printf(theme.ColorRed+"\r[down]"+theme.ColorReset+" ⤵️: %v\n", time.Now().UTC())

	if config.MonitorWebhook != "" {
		msg := fmt.Sprintf(`{"content": "[down] ⤵️: %s"}`, serverAddress)
		hook := exec.Command("curl", "-H", "Content-type: application/json", "-d", msg,
			config.MonitorWebhook)
		hook.Run()
	}
}

func Monitor(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"monitor"+theme.ColorGray+" [ip] [port] [interval-seconds]"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  📡 watch infra for up/down state changes with rctf\n")

			os.Exit(0)
		}
	}

	var ip string
	var port int
	util.GetRemoteParams(args, &ip, &port)

	serverAddress := fmt.Sprintf("%s:%v", ip, port)

	if len(args) > 2 {
		intervalArg, err := strconv.Atoi(args[2])
		if err != nil {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"%s\"!\n", err)
		}

		if intervalArg < 10 {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": interval of \"%v\" seconds too smol!\n", intervalArg)
		}

		montitorScanInterval = time.Duration(intervalArg) * time.Second
	}

	fmt.Printf(theme.ColorGray+"interval: "+theme.ColorYellow+"%v seconds"+theme.ColorReset+"\n", montitorScanInterval)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go waitForTerm(sigChan)

	go monitorServer(serverAddress)

	fmt.Printf(theme.ColorGray+"starting scan: "+theme.ColorReset+"%v\n", time.Now().UTC())
	fmt.Println(theme.ColorPurple + "press " + theme.ColorCyan + "ctrl+c " + theme.ColorPurple + "to exit..." + theme.ColorReset)

	if config.MonitorWebhook != "" {
		msg := fmt.Sprintf(`{"content": "starting monitoring: %s"}`, serverAddress)
		hook := exec.Command("curl", "-H", "Content-type: application/json", "-d", msg,
			config.MonitorWebhook)
		hook.Run()
	}

	go monitorSpinner()

	select {}
}
