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
		Name:  "rsa",
		Emoji: "🔐",
		Func:  Rsa,
		Help:  RsaHelp,
		Arguments: []Argument{
			{
				Name:     "--p",
				Optional: true,
				List:     false,
			},
			{
				Name:     "--q",
				Optional: true,
				List:     false,
			},
			{
				Name:     "--e",
				Optional: true,
				List:     false,
			},
			{
				Name:     "--d",
				Optional: true,
				List:     false,
			},
			{
				Name:     "--n",
				Optional: true,
				List:     false,
			},
			{
				Name:     "--c",
				Optional: true,
				List:     false,
			},
		}})
}

func RsaHelp() string {
	return "solve simple rsa tasks with ret\n\n" +

		"this command works by applying strategies to the given parameters that look for plaintext that consists of entirely ascii printable bytes\n" +
		"as a result it is well suited to finding flags for ctf tasks but not as a general purpose integer factorization tool\n\n" +

		theme.ColorGray + "arguments:" + theme.ColorReset + "\n" +
		"can be supplied as either base 10 or base 16 strings and the base will be inferred automatically\n" +
		"e.g. " + theme.ColorPurple + "FEED01234" + theme.ColorReset + " will be treated as a base 16 string and " + theme.ColorPurple + "123456789" + theme.ColorReset + " will be treated as a base 10 string\n" +
		"you can supply arguments the most common prefixes i.e. " + theme.ColorBlue + "x= -x= --x= " + theme.ColorReset + "where x is one of {p, q, e, d, n, c}\n" +
		"multiple values can be supplied as a list or with multiple argument prefixes e.g. " + theme.ColorBlue + "-n=1,2,3 or -n=1 -n=2 -n=3" + theme.ColorReset + "\n\n" +

		theme.ColorGray + "optional dependencies:" + theme.ColorReset + "\n" +
		"this command opportunistically makes use of other tools to perform compute intensive factorization\n" +
		" - gmp-ecm\n" +
		" - pari-gp\n\n" +

		"for example:\n" +
		"```bash\n" +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret rsa -n=1807415580361109435231633835400969 -e=65537 -c=1503532357945764445345675481376484\n" + theme.ColorReset +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret rsa -n=0x591ccab6e6a72f019cf942f99f09 -e=0x10001 -c=0x4a213f10d6c08b78ff5c0562e6e4\n" + theme.ColorReset +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret rsa -n=147879229115615272273161474028448405953 -e=3 -c=11160123069268350498833916853402276143\n" + theme.ColorReset +
		"```\n\n"
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
