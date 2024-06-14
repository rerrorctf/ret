package commands

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"ret/theme"
	"strconv"
	"strings"
)

func proxyList() {
	ps := exec.Command("ps", "aux")

	psOutput, err := ps.StdoutPipe()
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	grepSsh := exec.Command("grep", "ssh.*-L")
	grepSsh.Stdin = psOutput

	var output bytes.Buffer
	grepSsh.Stdout = &output

	if err := ps.Start(); err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}
	if err := grepSsh.Start(); err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}
	if err := ps.Wait(); err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}
	if err := grepSsh.Wait(); err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	lines := strings.Split(output.String(), "\n")
	for idx, line := range lines {
		if line == "" {
			continue
		}
		if strings.Contains(line, "grep") {
			continue
		}
		fields := strings.Fields(line)
		pid := fields[1]
		forward := fields[13]
		vps := fields[14]
		fmt.Printf(theme.ColorGray+"[%d] "+theme.ColorPurple+"%s "+theme.ColorYellow+"%s "+theme.ColorGray+"pid="+theme.ColorGreen+"%s"+theme.ColorReset+"\n", idx, forward, vps, pid)
	}
}

func proxyCreate(ip string, port int, vps string) {
	currentUser, err := user.Current()
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	proxy := exec.Command("ssh", "-Nf", "-L", fmt.Sprintf("%d:%s:%d", port, ip, port), fmt.Sprintf("%s@%s", currentUser.Name, vps))

	proxy.Stdin = os.Stdin
	proxy.Stdout = os.Stdout
	proxy.Stderr = os.Stderr

	err = proxy.Run()
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}
}

func proxyHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "proxy" + theme.ColorGray + " ip port vps-ip" + theme.ColorReset + "\n")
	fmt.Printf("  📡 proxy using ssh with ret\n")
	fmt.Printf("  specify no args to list current proxies\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/proxy.go" + theme.ColorReset + "\n")
	os.Exit(-1)
}

func Proxy(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			proxyHelp()
			return
		case "list":
			proxyList()
			return
		}
		if len(args) < 3 {
			fmt.Printf("💥 " + theme.ColorRed + " error" + theme.ColorReset + ": not enough args\n")
			proxyHelp()
			return
		}
		ip := args[0]
		port, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
			return
		}
		vps := args[2]
		proxyCreate(ip, port, vps)
		return
	}

	proxyList()
}
