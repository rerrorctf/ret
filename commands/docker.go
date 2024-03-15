package commands

import (
	"fmt"
	"log"
	"os"
	"rctf/theme"
	"rctf/util"
)

func makeDockerFile(port int) {
	binary := util.GuessBinary()

	dockerfile := fmt.Sprintf(
		"#\n# Dockerfile template made with 🚩 https://github.com/rerrorctf/rctf 🚩\n#\n\n"+
			"FROM ubuntu:24.04\n\n"+
			"RUN apt update && apt install -y socat\n\n"+
			"RUN groupadd --gid 1001 pwn\n\n"+
			"RUN useradd --uid 1001 --gid 1001 --home-dir /home/pwn --create-home --shell /sbin/nologin pwn\n\n"+
			"WORKDIR /home/pwn\n\n"+
			"COPY %s .\n\n"+
			"RUN echo \"flag{example}\" > flag.txt\n\n"+
			"RUN chmod +x ./%s\n\n"+
			"EXPOSE %d\n\n"+
			"USER pwn\n\n"+
			"CMD [\"socat\", \"tcp-listen:%d,fork,reuseaddr\", \"exec:./%s\"]\n",
		binary, binary, port, port, binary)

	err := os.WriteFile("Dockerfile", []byte(dockerfile), 0644)
	if err != nil {
		log.Fatalln("error writing to file:", err)
	}

	compose := fmt.Sprintf(
		"#\n# compose.yml template made with 🚩 https://github.com/rerrorctf/rctf 🚩\n#\n\n"+
			"services:\n"+
			"    task:\n"+
			"        build: .\n"+
			"        ports:\n"+
			"            - %d:%d\n",
		port, port)

	err = os.WriteFile("compose.yml", []byte(compose), 0644)
	if err != nil {
		log.Fatalln("error writing to file:", err)
	}

	fmt.Printf("🐋 " + theme.ColorGray + "ready to run:" + theme.ColorReset + " $ sudo docker compose up --build -d\n")
}

func Docker(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			fmt.Fprintf(os.Stderr, theme.ColorGreen+"usage"+theme.ColorReset+": rctf "+theme.ColorBlue+"docker"+theme.ColorGray+" [ip] [port]"+theme.ColorReset+"\n")
			fmt.Fprintf(os.Stderr, "  🐋 create a dockerfile template with rctf\n")
			os.Exit(0)
		}
	}

	_, err := os.Stat("./Dockerfile")
	if !os.IsNotExist(err) {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": \"Dockerfile\" already exists!\n")
	}

	_, err = os.Stat("./compose.yml")
	if !os.IsNotExist(err) {
		log.Fatalf("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": \"compose.yml\" already exists!\n")
	}

	var ip string
	var port int
	util.GetRemoteParams(args, &ip, &port)

	makeDockerFile(port)
}
