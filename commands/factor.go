package commands

import (
	"fmt"
	"log"
	"math/big"
	"ret/theme"
	"ret/util"
	"strings"
	"sync"
)

var (
	N []*big.Int
)

func init() {
	Commands = append(Commands, Command{
		Name:  "factor",
		Emoji: "🪓",
		Func:  Factor,
		Help:  FactorHelp,
		Arguments: []Argument{
			{
				Name:     "--n",
				Optional: true,
				List:     false,
			},
		}})
}

func FactorHelp() string {
	return "factor with ret\n" +

		"arguments can be supplied as either base 10 or base 16 strings and the base will be inferred automatically\n\n" +
		"for example " + theme.ColorPurple + "FEED01234" + theme.ColorReset + " will be treated as a base 16 string and " + theme.ColorPurple + "123456789" + theme.ColorReset + " will be treated as a base 10 string\n\n" +
		"you can supply arguments the most common prefixes i.e. " + theme.ColorBlue + "n= -n= --n= " + theme.ColorReset + "\n\n" +
		"multiple values can be supplied as a list or with multiple argument prefixes e.g. " + theme.ColorBlue + "-n=1,2,3 or -n=1 -n=2 -n=3" + theme.ColorReset + "\n\n" +

		"for example:\n" +
		"```bash\n" +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret factor -n=1807415580361109435231633835400969\n" + theme.ColorReset +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret factor -n=0x591ccab6e6a72f019cf942f99f09\n" + theme.ColorReset +
		theme.ColorGray + "$ " + theme.ColorBlue + "ret factor -n=147879229115615272273161474028448405953\n" + theme.ColorReset +
		"```\n\n"
}

func parseFactorArgs(args []string) {
	if len(args) == 0 {
		log.Fatalln("💥 " + theme.ColorRed + "error" + theme.ColorReset + ": expected 1 or more args")
	}

	for _, arg := range args {
		arg = strings.ReplaceAll(arg, "-", "")

		if strings.HasPrefix(arg, "n=") {
			util.ParseBigInts(&N, arg[2:])
		} else {
			fmt.Printf("😰"+theme.ColorGray+" \""+theme.ColorReset+"%v"+theme.ColorGray+"\""+theme.ColorRed+
				" could not be parsed"+theme.ColorReset+"\n", arg)
		}
	}
}

func Factor(args []string) {
	parseFactorArgs(args)

	var wg sync.WaitGroup

	for _, n := range N {
		wg.Add(1)

		go func() {
			defer wg.Done()
			factors, url, err := util.FactorDB(n)
			if err != nil {
				log.Fatalf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
			}

			if factors == nil {
				return
			}

			if len(factors) == 0 {
				return
			}

			fmt.Printf("%v\n%v\n", factors, url)
		}()
	}

	wg.Wait()
}
