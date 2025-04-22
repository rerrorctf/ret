package commands

import (
	"fmt"
	"ret/config"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "remote",
		Emoji: "📡",
		Func:  Remote,
		Help:  RemoteHelp,
		Arguments: []Argument{
			{
				Name:     "ip",
				Optional: true,
				List:     false,
				Default:  "127.0.0.1",
			},
			{
				Name:     "port",
				Optional: true,
				List:     false,
				Default:  "9001",
			},
		},
		SeeAlso: nil})
}

func RemoteHelp() string {
	return "set or query a task's ip and port with ret\n\n" +
		"supply no arguments to see the current ip and port\n\n" +
		"note that task metadata is stored in hidden directory " + theme.ColorCyan + "`.ret`" + theme.ColorReset + " and therefore scoped to the cwd\n\n" +
		"task metadata is stored in the " + theme.ColorCyan + "`" + config.TaskFileName + "`" + theme.ColorReset + " file\n"
}

func displayCurrentTaskIpAndPort() {
	ip := util.GetCurrentTaskIp()
	port := util.GetCurrentTaskPort()

	fmt.Printf("📡 "+theme.ColorBlue+"%s:%d"+theme.ColorReset+"\n", ip, port)
}

func setCurrentTaskIpAndPort(newIp string, newPort int) {
	oldIp := util.GetCurrentTaskIp()
	oldPort := util.GetCurrentTaskPort()

	if (oldIp != newIp) || (oldPort != newPort) {
		fmt.Printf(theme.ColorGray+"📡 changing ip:port from: "+theme.ColorRed+"%s:%d"+theme.ColorGray+" to: "+theme.ColorGreen+"%s:%d"+theme.ColorReset+"\n",
			oldIp, oldPort, newIp, newPort)
	} else {
		fmt.Printf(theme.ColorGray+"📡 setting ip:port to: "+theme.ColorGreen+"%s:%d"+theme.ColorReset+"\n", newIp, newPort)
	}

	util.SetCurrentTaskIp(newIp)
	util.SetCurrentTaskPort(newPort)
}

func Remote(args []string) {
	if len(args) == 0 {
		displayCurrentTaskIpAndPort()
		return
	}

	util.EnsureSkeleton()

	var ip string
	var port int
	util.GetRemoteParams(args, &ip, &port)

	setCurrentTaskIpAndPort(ip, port)
}
