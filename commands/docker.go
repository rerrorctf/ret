package commands

import (
	"fmt"
	"log"
	"os"
	"ret/theme"
	"ret/util"
)

func makeDockerFile(port int) {
	binary := util.GuessBinary()

	dockerfile := fmt.Sprintf(
		"FROM ubuntu:24.04\n\n"+
			"RUN apt update && apt install -y socat\n\n"+
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
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": ret "+theme.ColorBlue+"docker"+theme.ColorGray+" [ip] [port]"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  🐋 create a dockerfile from a template with ret\n")
			fmt.Fprintf(os.Stderr, "  🔗 "+theme.ColorGray+"https://github.com/rerrorctf/ret/blob/main/commands/docker.go"+theme.ColorReset+"\n")
			os.Exit(0)
		}
	}

	_, err := os.Stat("./Dockerfile")
	if !os.IsNotExist(err) {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": \"Dockerfile\" already exists!\n")
	}

	var ip string
	var port int
	util.GetRemoteParams(args, &ip, &port)

	makeDockerFile(port)
}
