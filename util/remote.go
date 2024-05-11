package util

import (
	"fmt"
	"log"
	"ret/theme"
	"strconv"
)

func GetRemoteParams(args []string, ip *string, port *int) {
	if len(args) > 0 {
		fmt.Printf(theme.ColorGray+"ip: "+theme.ColorYellow+"%s"+theme.ColorReset+"\n", args[0])
		*ip = args[0]
	} else {
		*ip = "127.0.0.1"
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
		*port = 9001
	}
}
