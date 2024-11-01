package commands

import (
	"fmt"
	"log"
	"os"
	"ret/theme"
	"ret/util"
)

func init() {
	Commands = append(Commands, Command{
		Name:  "docker",
		Emoji: "🐋",
		Func:  Docker,
		Help:  DockerHelp,
		Arguments: []Argument{
			{
				Name:     "ip",
				Optional: true,
				List:     false,
			},
			{
				Name:     "port",
				Optional: true,
				List:     false,
			},
		}})
}

func DockerHelp() string {
	return "create a dockerfile from a template with ret\n"
}

func makeDockerFile(port int) {
	binaries := util.GuessBinary()

	binary := binaries[0]

	dockerfile := fmt.Sprintf(
		"FROM ubuntu:24.04\n\n"+
			"RUN apt update && apt upgrade -y && apt install -y socat\n\n"+
			"COPY %s .\n\n"+
			"RUN echo \"flag{example}\" > flag.txt\n\n"+
			"RUN chmod +x ./%s\n\n"+
			"EXPOSE %d\n\n"+
			"CMD [\"socat\", \"tcp-listen:%d,fork,reuseaddr\", \"exec:./%s\"]\n",
		binary, binary, port, port, binary)

	err := os.WriteFile("Dockerfile", []byte(dockerfile), 0644)
	if err != nil {
		log.Fatalln("error writing to file:", err)
	}

	fmt.Printf("🐋 "+theme.ColorGray+"ready to run:"+theme.ColorReset+" $ sudo docker build -t task . && sudo docker run -p %d:%d task\n", port, port)
}

func Docker(args []string) {
	var ip string
	var port int
	util.GetRemoteParams(args, &ip, &port)

	_, err := os.Stat("./Dockerfile")
	if !os.IsNotExist(err) {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": \"Dockerfile\" already exists!\n"+
			"🐋 "+theme.ColorGray+"ready to run:"+theme.ColorReset+" $ sudo docker build -t task . && sudo docker run -p %d:%d task\n", port, port)
	}

	makeDockerFile(port)
}
