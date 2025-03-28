package rsa

import (
	"fmt"
	"log"
	"math/big"
	"ret/theme"
	"ret/util"
)

func init() {
	Strategies = append(Strategies, Strategy{
		Name: "factordb",
		Func: StrategyFactorDB,
	})
}

func scriptFactorDB(url string, p *big.Int, q *big.Int, n *big.Int, e *big.Int, c *big.Int, mBytes []byte) {
	fmt.Printf(
		"\n```python\n"+
			"#!/usr/bin/env python3\n\n"+
			"n = %s\n"+
			"e = %s\n"+
			"c = %s\n\n"+
			"# %s\n"+
			"p = %s\n"+
			"q = %s\n"+
			"assert((p * q) == n)\n\n"+
			"phi = (p - 1) * (q - 1)\n"+
			"d = pow(e, -1, phi)\n"+
			"m = pow(c, d, n)\n\n"+
			"flag = m.to_bytes(length=(m.bit_length() + 7) // 8, byteorder=\"big\")\n"+
			"print(flag.decode()) # %s\n```\n\n",
		n, e, c, url, p, q, mBytes)
}

func scriptFactorDBManyFactors(url string, factors []*big.Int, n *big.Int, e *big.Int, c *big.Int, mBytes []byte) {
	script := fmt.Sprintf(
		"\n```python\n"+
			"#!/usr/bin/env python3\n\n"+
			"n = %s\n"+
			"e = %s\n"+
			"c = %s\n\n"+
			"# %s\n"+
			"factors = [\n",
		n, e, c, url)

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

func factorDB(strategy *Strategy, n *big.Int) {
	factors, url, err := util.FactorDB(n)

	if err != nil {
		log.Fatalf("💥 "+theme.ColorRed+"error"+theme.ColorReset+": %v\n", err)
	}

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

				scriptFactorDB(url, p, q, n, e, c, mBytes)
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

				scriptFactorDBManyFactors(url, factors, n, e, c, mBytes)
			}
		}
	}
}

func StrategyFactorDB(strategy *Strategy) {
	for _, n := range N {
		factorDB(strategy, n)
	}
}

// examples:
// n = 66082519841206442253261420880518905643648844231755824847819839195516869801231
// e = 65537
// c = 19146395818313260878394498164948015155839880044374872805448779372117637653026
//
// n = 51328431690246050000196200646927542588629192646276628974445855970986472407007
// e = 65537
// c = 9015202564552492364962954854291908723653545972440223723318311631007329746475
