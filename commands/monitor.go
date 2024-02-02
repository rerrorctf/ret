package commands

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"rctf/theme"
	"rctf/util"
	"syscall"
	"time"
)

const (
	montitorScanInterval = 30
)

func monitorSpinner() {
	interval := 500 * time.Millisecond

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

func Monitor(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"monitor"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  📡 watch infra for up/down state changes with rctf\n")

			os.Exit(0)
		}
	}

	var ip string
	var port int
	util.GetRemoteParams(args, &ip, &port)

	serverAddress := fmt.Sprintf("%s:%v", ip, port)

	sigChan := make(chan os.Signal, 1)

	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\r\n👋")
		os.Exit(0)
	}()

	go func(serverAddress string) {
		connected := false
		for {
			_, err := net.DialTimeout("tcp", serverAddress, montitorScanInterval*time.Second)
			if err != nil {
				if connected {
					// no longer connected...
					fmt.Printf(theme.ColorRed+"\r[down]"+theme.ColorReset+" ⤵️: %v\n", time.Now().UTC())
					connected = false
				}

			} else {
				if !connected {
					// now connected!
					fmt.Printf(theme.ColorGreen+"\r[conn]"+theme.ColorReset+" ⤴️: %v\n", time.Now().UTC())
					connected = true
				}
			}

			time.Sleep(montitorScanInterval * time.Second)
		}
	}(serverAddress)

	fmt.Printf("starting scan: %v\n", time.Now().UTC())
	fmt.Println(theme.ColorPurple + "press " + theme.ColorCyan + "ctrl+c " + theme.ColorPurple + "to exit..." + theme.ColorReset)
	go monitorSpinner()
	select {}
}
