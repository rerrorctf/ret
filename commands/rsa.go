package commands

import (
	"fmt"
	"log"
	"ret/rsa"
	"ret/theme"
	"ret/util"
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
		},
		SeeAlso: []string{"factor"}})
}

func RsaHelp() string {
	return "solve simple rsa tasks with ret\n\n" +

		"this command works by applying strategies to the given parameters that look for plaintext that consists of entirely ascii printable bytes\n\n" +
		"as a result it is well suited to finding flags for ctf tasks but not as a general purpose integer factorization tool\n\n" +

		"arguments can be supplied as either base 10 or base 16 strings and the base will be inferred automatically\n\n" +
		"for example " + theme.ColorPurple + "FEED01234" + theme.ColorReset + " will be treated as a base 16 string and " + theme.ColorPurple + "123456789" + theme.ColorReset + " will be treated as a base 10 string\n\n" +
		"you can supply arguments the most common prefixes i.e. " + theme.ColorBlue + "x= -x= --x= " + theme.ColorReset + "where x is one of {p, q, e, d, n, c}\n\n" +
		"multiple values can be supplied as a list or with multiple argument prefixes e.g. " + theme.ColorBlue + "-n=1,2,3 or -n=1 -n=2 -n=3" + theme.ColorReset + "\n\n" +

		"this command opportunistically makes use of the following tools to perform compute intensive factorization:\n\n" +
		" - gmp-ecm\n" +
		" - pari-gp\n\n" +

		theme.ColorYellow + "note" + theme.ColorReset + ": this command is essentially a work in progress as strategies are added over time\n\n" +

		"for example:\n" +
		"```bash\n" +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret rsa -n=1807415580361109435231633835400969 -e=65537 -c=1503532357945764445345675481376484\n" + theme.ColorReset +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret rsa -n=0x591ccab6e6a72f019cf942f99f09 -e=0x10001 -c=0x4a213f10d6c08b78ff5c0562e6e4\n" + theme.ColorReset +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret rsa -n=147879229115615272273161474028448405953 -e=3 -c=11160123069268350498833916853402276143\n" + theme.ColorReset +
		"```\n"
}

func parseRsaArgs(args []string) {
	if len(args) == 0 {
		log.Fatalln("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": expected 1 or more args")
	}

	for _, arg := range args {
		arg = strings.ReplaceAll(arg, "-", "")

		if strings.HasPrefix(arg, "p=") {
			util.ParseBigInts(&rsa.P, arg[2:])
		} else if strings.HasPrefix(arg, "q=") {
			util.ParseBigInts(&rsa.Q, arg[2:])
		} else if strings.HasPrefix(arg, "e=") {
			util.ParseBigInts(&rsa.E, arg[2:])
		} else if strings.HasPrefix(arg, "d=") {
			util.ParseBigInts(&rsa.D, arg[2:])
		} else if strings.HasPrefix(arg, "n=") {
			util.ParseBigInts(&rsa.N, arg[2:])
		} else if strings.HasPrefix(arg, "c=") {
			util.ParseBigInts(&rsa.C, arg[2:])
		} else {
			fmt.Printf("😰"+theme.ColorGray+" \""+theme.ColorReset+"%v"+theme.ColorGray+"\""+theme.ColorRed+
				" could not be parsed"+theme.ColorReset+"\n", arg)
		}
	}
}

func Rsa(args []string) {
	parseRsaArgs(args)

	rsa.Rsa()
}
