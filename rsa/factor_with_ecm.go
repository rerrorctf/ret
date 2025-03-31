package rsa

import (
	"fmt"
	"log"
	"math/big"
	"ret/theme"
	"ret/util"
	"sync"
)

func init() {
	Strategies = append(Strategies, Strategy{
		Name: "factor_with_ecm",
		Func: StrategyFactorWithECM,
	})
}

func scriptFactorECM(cmd string, p *big.Int, q *big.Int, n *big.Int, e *big.Int, c *big.Int, mBytes []byte) {
	fmt.Printf(
		"\n```python\n"+
			"#!/usr/bin/env python3\n\n"+
			"n = %s\n"+
			"e = %s\n"+
			"c = %s\n\n"+
			"# factored with gmp-ecm ~ \"%s\"\n"+
			"p = %s\n"+
			"q = %s\n"+
			"assert((p * q) == n)\n\n"+
			"phi = (p - 1) * (q - 1)\n"+
			"d = pow(e, -1, phi)\n"+
			"m = pow(c, d, n)\n\n"+
			"flag = m.to_bytes(length=(m.bit_length() + 7) // 8, byteorder=\"big\")\n"+
			"print(flag.decode()) # %s\n```\n\n",
		n, e, c, cmd, p, q, mBytes)
}

func scriptFactorECMManyFactors(cmd string, factors []*big.Int, n *big.Int, e *big.Int, c *big.Int, mBytes []byte) {
	script := fmt.Sprintf(
		"\n```python\n"+
			"#!/usr/bin/env python3\n\n"+
			"n = %s\n"+
			"e = %s\n"+
			"c = %s\n\n"+
			"# factored with gmp-ecm ~ \"%s\"\n"+
			"factors = [\n",
		n, e, c, cmd)

	for _, factor := range factors {
		script += fmt.Sprintf("    %s,\n", factor)
	}

	script += fmt.Sprintf(
		"]\n\n"+
			"np = 1\n"+
			"for factor in factors:\n"+
			"    np *= factor\n"+
			"assert(np == n)\n\n"+
			"phi = 1\n"+
			"for factor in factors:\n"+
			"    phi *= factor - 1\n"+
			"\n"+
			"d = pow(e, -1, phi)\n"+
			"m = pow(c, d, n)\n\n"+
			"flag = m.to_bytes(length=(m.bit_length() + 7) // 8, byteorder=\"big\")\n"+
			"print(flag.decode()) # %s\n```\n\n",
		mBytes)

	fmt.Print(script)
}
func factorWithECM(strategy *Strategy, n *big.Int) {
	factors, cmdStr, err := util.FactorWithECM(n)

	if err != nil {
		log.Printf("💥 "+theme.ColorRed+" error"+theme.ColorReset+": %v\n", err)
		return
	}

	fmt.Printf("["+theme.ColorGreen+"%s"+theme.ColorReset+"] "+theme.ColorPurple+"%v"+theme.ColorReset+"\n", strategy.Name, factors)

	if len(factors) == 2 {
		// special case for N = p * q where p and q and two distinct primes
		p := factors[0]
		q := factors[1]
		for _, e := range E {
			for _, c := range C {
				phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
				d := new(big.Int).Exp(e, big.NewInt(-1), phi)
				m := new(big.Int).Exp(c, d, n)

				mBytes := ResultChecker(strategy, m)

				if mBytes == nil {
					continue
				}

				scriptFactorECM(cmdStr, p, q, n, e, c, mBytes)
			}
		}
	} else {
		// general case for N = the product of a series of prime factors
		for _, e := range E {
			for _, c := range C {
				phi := big.NewInt(1)
				for _, factor := range factors {
					phi.Mul(phi, new(big.Int).Sub(factor, big.NewInt(1)))
				}

				d := new(big.Int).Exp(e, big.NewInt(-1), phi)
				m := new(big.Int).Exp(c, d, n)

				mBytes := ResultChecker(strategy, m)

				if mBytes == nil {
					continue
				}

				scriptFactorECMManyFactors(cmdStr, factors, n, e, c, mBytes)
			}
		}
	}
}

func StrategyFactorWithECM(strategy *Strategy) {
	installed := util.CheckIfECMInstalled()
	if installed != true {
		return
	}

	var wg sync.WaitGroup

	for _, n := range N {
		wg.Add(1)

		go func() {
			defer wg.Done()
			factorWithECM(strategy, n)
		}()
	}

	wg.Wait()
}

// examples:
//
// many small primes
// n = 580642391898843192929563856870897799650883152718761762932292482252152591279871421569162037190419036435041797739880389529593674485555792234900969402019055601781662044515999210032698275981631376651117318677368742867687180140048715627160641771118040372573575479330830092989800730105573700557717146251860588802509310534792310748898504394966263819959963273509119791037525504422606634640173277598774814099540555569257179715908642917355365791447508751401889724095964924513196281345665480688029639999472649549163147599540142367575413885729653166517595719991872223011969856259344396899748662101941230745601719730556631637
// e = 65537
// c = 9015202564552492364962954854291908723653545972440223723318311631007329746475
//
// 2x small primes
// n = 1807415580361109435231633835400969
// e = 65537
// c = 1503532357945764445345675481376484
//
// 3x small primes
// n = 190209468605777663603644732778418652613552593605359
// e = 65537
// c = 90571159227971972121059021184318089901439721540089
