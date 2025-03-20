package commands

import (
	"fmt"
	"log"
	"math/big"
	"ret/rsa"
	"ret/theme"
	"strings"
)

func init() {
	Commands = append(Commands, Command{
		Name:      "rsa",
		Emoji:     "🔐",
		Func:      Rsa,
		Help:      RsaHelp,
		Arguments: nil})
}

func RsaHelp() string {
	return "rsa with ret\n"
}

func looksLikeBase16(arg string) bool {
	for _, c := range arg {
		if c > rune('9') {
			return true
		}
	}

	return false
}

func parseBigInt(arg string) *big.Int {
	if looksLikeBase16(arg) {
		if strings.HasPrefix(arg, "0x") || strings.HasPrefix(arg, "0X") {
			arg = arg[2:]
		}

		X, _ := new(big.Int).SetString(arg, 16)
		return X
	}

	X, _ := new(big.Int).SetString(arg, 10)
	return X
}

func parseBigInts(XS *[]*big.Int, arg string) {
	xs := strings.Split(arg, ",")
	for _, x := range xs {
		X := parseBigInt(x)
		if X == nil {
			fmt.Printf("😰"+theme.ColorGray+" \""+theme.ColorReset+"%v"+theme.ColorGray+"\""+theme.ColorRed+
				" could not be parsed"+theme.ColorReset+"\n", x)
			continue
		}

		*XS = append(*XS, X)
	}
}

func parseArgs(args []string) {
	if len(args) == 0 {
		log.Fatalln("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": expected 1 or more args")
	}

	for _, arg := range args {
		arg = strings.ReplaceAll(arg, "-", "")

		if strings.HasPrefix(arg, "p=") {
			parseBigInts(&rsa.P, arg[2:])
		} else if strings.HasPrefix(arg, "q=") {
			parseBigInts(&rsa.Q, arg[2:])
		} else if strings.HasPrefix(arg, "e=") {
			parseBigInts(&rsa.E, arg[2:])
		} else if strings.HasPrefix(arg, "d=") {
			parseBigInts(&rsa.D, arg[2:])
		} else if strings.HasPrefix(arg, "n=") {
			parseBigInts(&rsa.N, arg[2:])
		} else if strings.HasPrefix(arg, "c=") {
			parseBigInts(&rsa.C, arg[2:])
		} else {
			fmt.Printf("😰"+theme.ColorGray+" \""+theme.ColorReset+"%v"+theme.ColorGray+"\""+theme.ColorRed+
				" could not be parsed"+theme.ColorReset+"\n", arg)
		}
	}
}

func Rsa(args []string) {
	parseArgs(args)

	rsa.Rsa()
}
