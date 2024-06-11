package commands

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"ret/theme"
	"time"
)

func libcSpinner(stop chan bool) {
	emojis := []string{
		"🖱️", "⌨️", "🔧", "⚙️", "📂", "📁", "💾", "📟", "🛠️",
		"🔌", "📡", "🔍", "💿", "🖨️", "🧰", "🔒", "📜", "🚩",
		"🇱", "🇮", "🇧", "🇨",
	}

	for {
		for _, e := range emojis {
			select {
			case <-stop:
				return
			default:
				fmt.Printf("\r%s", e)
				time.Sleep(200 * time.Millisecond)
			}

		}
	}
}

func libcHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "libc" + theme.ColorGray + " [tag]" + theme.ColorReset + "\n")
	fmt.Printf("  🗽 get a version of libc by copying it from a docker container with ret\n")
	fmt.Printf("     " + theme.ColorGray + "specify an image tag like \"ubuntu:24.04\" to get a specific version" + theme.ColorReset + "\n")
	fmt.Printf("     " + theme.ColorGray + "without args this command will use the tag \"ubuntu:latest\"" + theme.ColorReset + "\n")
	fmt.Printf("     " + theme.ColorGray + "the file will be copied to the cwd and added with ret" + theme.ColorReset + "\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/libc.go" + theme.ColorReset + "\n")
	os.Exit(0)
}

func Libc(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			libcHelp()
		}
	}

	stop := make(chan bool)

	go libcSpinner(stop)

	tag := "ubuntu:latest"

	if len(args) > 0 {
		tag = args[0]
	}

	dir, err := os.MkdirTemp("", "ret-libc-")
	if err != nil {
		fmt.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		os.Exit(1)
	}

	setup := "#!/bin/sh\n\n" +
		"update_apt() {\n" +
		"\tapt update\n" +
		"\tapt upgrade -y\n" +
		"}\n\n" +
		"update_pacman() {\n" +
		"\tpacman -Syu --noconfirm\n" +
		"}\n\n" +
		"if command -v apt >/dev/null 2>&1; then\n" +
		"\tupdate_apt\n" +
		"elif command -v pacman >/dev/null 2>&1; then\n" +
		"\tupdate_pacman\n" +
		"else\n" +
		"\techo \"Unsupported package manager\"\n" +
		"exit 1\n" +
		"fi\n"

	err = os.WriteFile(dir+"/setup.sh", []byte(setup), 0744)
	if err != nil {
		log.Fatalln("error writing to file:", err)
	}

	dockerfile := fmt.Sprintf(
		"FROM %s\n\n"+
			"COPY setup.sh .\n"+
			"RUN ./setup.sh\n"+
			"CMD [\"sh\"]\n",
		tag)

	err = os.WriteFile(dir+"/Dockerfile", []byte(dockerfile), 0644)
	if err != nil {
		log.Fatalln("error writing to file:", err)
	}

	script := fmt.Sprintf(
		"docker build -t ret-libc .\n"+
			"docker run -d --name ret-libc-container ret-libc tail -f /dev/null\n"+
			"docker cp ret-libc-container:/lib/x86_64-linux-gnu/libc.so.6 ./%s.libc.so.6\n"+
			"docker cp ret-libc-container:/usr/lib/libc.so.6 ./%s.libc.so.6\n"+
			"docker stop ret-libc-container\n"+
			"docker rm ret-libc-container\n", tag, tag)

	err = os.WriteFile(dir+"/go.sh", []byte(script), 0644)
	if err != nil {
		log.Fatalln("error writing to file:", err)
	}

	err = os.Chmod(dir+"/go.sh", 0744)
	if err != nil {
		log.Fatalln("error chmoding file:", err)
	}

	libc := exec.Command("bash", "-c", "(cd "+dir+" && sudo ./go.sh)")

	err = libc.Run()
	if err != nil {
		log.Fatalln(err)
	}

	stop <- true

	fmt.Printf("\r")

	Add([]string{dir + "/" + tag + ".libc.so.6"})
}
