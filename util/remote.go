package util

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"rctf/theme"
	"strconv"
)

func GetRemoteParams(args []string, ip *string, port *int) {
	scanner := bufio.NewScanner(os.Stdin)

	if len(args) > 0 {
		fmt.Printf(theme.ColorGray+"ip: "+theme.ColorYellow+"%s"+theme.ColorReset+"\n", args[0])
		*ip = args[0]
	} else {
		fmt.Print(theme.ColorGray + "enter remote ip (no port): " + theme.ColorReset)
		scanner.Scan()
		*ip = scanner.Text()
		fmt.Printf(theme.ColorReset)
	}

	if len(args) > 1 {
		p, err := strconv.Atoi(args[1])

		if err != nil {
			log.Fatalln("💥 "+theme.ColorRed+"error"+theme.ColorReset+": reading port:", err)
		}

		if p < 1 || p > 65535 {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": invalid port %v\n", port)
		}

		fmt.Printf(theme.ColorGray+"port: "+theme.ColorYellow+"%v"+theme.ColorReset+"\n", p)

		*port = p
	} else {
		fmt.Print(theme.ColorGray + "enter remote port: " + theme.ColorReset)
		scanner.Scan()
		fmt.Printf(theme.ColorReset)

		p, err := strconv.Atoi(scanner.Text())

		if err != nil {
			log.Fatalln("💥 "+theme.ColorRed+"error"+theme.ColorReset+": reading port", err)
		}

		if p < 1 || p > 65535 {
			log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": invalid port %v\n", port)
		}

		*port = p
	}
}
