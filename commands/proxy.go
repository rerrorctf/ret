package commands

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"ret/theme"
	"strconv"
	"strings"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "proxy",
		Emoji: "📡",
		Func:  Proxy,
		Help:  ProxyHelp,
		Url:   "https://github.com/rerrorctf/ret/blob/main/commands/proxy.go",
		Arguments: []Argument{
			{
				Name:     "list/create",
				Optional: true,
				List:     false,
			},
		}})
}

func ProxyHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "proxy" + theme.ColorGray + " [list/create]" + theme.ColorReset + "\n")
	fmt.Printf("  📡 manage proxies with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/proxy.go" + theme.ColorReset + "\n")
}

func proxyList() {
	ps := exec.Command("ps", "aux")

	psOutput, err := ps.StdoutPipe()
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	grepSsh := exec.Command("grep", "ssh.*-L")
	grepSsh.Stdin = psOutput

	var output bytes.Buffer
	grepSsh.Stdout = &output

	if err := ps.Start(); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
	if err := grepSsh.Start(); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
	if err := ps.Wait(); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
	if err := grepSsh.Wait(); err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
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
		fmt.Printf(theme.ColorGray+"📡 [%02d]\t"+theme.ColorPurple+"%s "+theme.ColorYellow+"%s "+theme.ColorGray+"pid="+theme.ColorGreen+"%s"+theme.ColorReset+" ", idx, forward, vps, pid)
		fmt.Printf(theme.ColorBlue+"\"nc 127.0.0.1 %s\""+theme.ColorReset+"\n", strings.Split(forward, ":")[0])
	}
}

func proxyCreate(localPort int, remoteIp string, remotePort int, proxyIp string) {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	proxy := exec.Command("ssh", "-Nf", "-L", fmt.Sprintf("%d:%s:%d", localPort, remoteIp, remotePort), fmt.Sprintf("%s@%s", currentUser.Name, proxyIp))

	proxy.Stdin = os.Stdin
	proxy.Stdout = os.Stdout
	proxy.Stderr = os.Stderr

	err = proxy.Run()
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}

func ProxyCreate(args []string) {
	if len(args) < 4 {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": expected local-port remote-ip remote-port proxy-ip\n")
		return
	}

	localPort, err := strconv.Atoi(args[0])
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	remoteIp := args[1]

	remotePort, err := strconv.Atoi(args[2])
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	// TODO make optional - use default vps if one exists
	proxyIp := args[3]

	proxyCreate(localPort, remoteIp, remotePort, proxyIp)
}

func Proxy(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "list":
			proxyList()
			return
		case "create":
			ProxyCreate(args[1:])
			return
		}
	}

	ProxyHelp()
}
