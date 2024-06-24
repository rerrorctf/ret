package commands

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"ret/theme"
	"ret/util"
)

func makeAngrScript() {
	binaries := util.GuessBinary()

	if len(binaries) > 1 {
		fmt.Printf("⚠️ multiple candidate binaries found\n")
		for _, binary := range binaries {
			fmt.Printf("%s\n", binary)
		}
	}

	binary := binaries[0]

	script := fmt.Sprintf(
		"import angr\n"+
			"import claripy\n\n"+
			"NUM_BYTES = 32\n\n"+
			"p = angr.Project(\"./%s\", main_opts={\"base_addr\": 0x100000}, auto_load_libs=False)\n\n"+
			"flag = claripy.BVS(\"flag\", NUM_BYTES * 8)\n\n"+
			"state = p.factory.full_init_state(stdin=flag, add_options=angr.options.unicorn)\n\n"+
			"sim = p.factory.simgr(state)\n\n"+
			"sim.explore(find=0x101234, avoid=0x101234)\n\n"+
			"print(sim.found[0].posix.dumps(0))\n",
		binary)

	err := os.WriteFile("go-angr.py", []byte(script), 0644)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	err = os.Chmod("go-angr.py", 0744)
	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

	fmt.Printf("😠 "+theme.ColorGray+"ready to get angry:"+theme.ColorReset+" $ ./%s\n", "go-angr.py")
}

func angrHelp() {
	fmt.Printf(theme.ColorGreen + "usage" + theme.ColorReset + ": ret " + theme.ColorBlue + "angr" + theme.ColorReset + "\n")
	fmt.Printf("  😠 open angr with ret\n")
	fmt.Printf("  🔗 " + theme.ColorGray + "https://github.com/rerrorctf/ret/blob/main/commands/angr.go" + theme.ColorReset + "\n")
}

func Angr(args []string) {
	if len(args) > 0 {
		switch args[0] {
		case "help":
			angrHelp()
			return
		}
	}

	_, err := os.Stat("./go-angr.py")
	if os.IsNotExist(err) {
		makeAngrScript()
	} else {
		fmt.Printf("⚠️ " + theme.ColorYellow + "warning" + theme.ColorReset + ": \"go-angr.py\" already exists!\n")
	}

	pull := exec.Command("sudo", "docker", "pull", "angr/angr")

	pull.Stdin = os.Stdin
	pull.Stdout = os.Stdout
	pull.Stderr = os.Stderr

	err = pull.Run()
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
