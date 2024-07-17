package commands

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"ret/theme"
)

func init() {
	Commands = append(Commands, Command{
		Name:      "angr",
		Emoji:     "😠",
		Func:      Angr,
		Help:      AngrHelp,
		Url:       "https://github.com/rerrorctf/ret/blob/main/commands/angr.go",
		Arguments: nil})
}

func AngrHelp() string {
	return "runs the angr docker with ret\n\n" +
		"mounts the current working directory as a volume\n\n" +
		"effectively runs:\n" +
		"```bash\n" +
		theme.ColorGray + "$ " + theme.ColorBlue + "sudo docker pull angr/angr\n" +
		theme.ColorGray + "$ " + theme.ColorBlue + "sudo docker run -it -v $PWD:/home/angr/x angr/angr\n" + theme.ColorReset +
		"```\n\n" +
		"see https://docs.angr.io/en/latest/getting-started/installing.html#installing-with-docker for more information\n" + theme.ColorReset
}

func Angr(args []string) {
	pull := exec.Command("sudo", "docker", "pull", "angr/angr")

	pull.Stdin = os.Stdin
	pull.Stdout = os.Stdout
	pull.Stderr = os.Stderr

	err := pull.Run()
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	dir, err := os.Getwd()
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	run := exec.Command("sudo", "docker", "run", "-it", "-v", fmt.Sprintf("%s:/home/angr/x", dir), "angr/angr")

	run.Stdin = os.Stdin
	run.Stdout = os.Stdout
	run.Stderr = os.Stderr

	err = run.Run()

	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}
}
