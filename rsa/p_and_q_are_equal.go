package rsa

import (
	"fmt"
	"math/big"
)

func init() {
	Strategies = append(Strategies, Strategy{
		Name: "p_and_q_are_equal",
		Func: StrategyPAndQAreEqual,
	})
}

func scriptPAndQAreEqual(n *big.Int, e *big.Int, c *big.Int, mBytes []byte) {
	fmt.Printf(
		"\n```python\n"+
			"#!/usr/bin/env python3\n\n"+
			"import gmpy2\n\n"+
			"n = %s\n"+
			"e = %s\n"+
			"c = %s\n\n"+
			"p = int(gmpy2.iroot(n, 2)[0])\n"+
			"q = p\n"+
			"assert((p * q) == n)\n\n"+
			"phi = p * (p - 1)\n"+
			"d = pow(e, -1, phi)\n"+
			"m = pow(c, d, n)\n\n"+
			"flag = m.to_bytes(length=(m.bit_length() + 7) // 8, byteorder=\"big\")\n"+
			"print(flag.decode()) # %s\n```\n",
		n, e, c, mBytes)
}

func pAndQAreEqual(strategy *Strategy, n *big.Int, e *big.Int, c *big.Int) {
	p := new(big.Int).Sqrt(n)

	phi := new(big.Int).Mul(p, new(big.Int).Sub(p, big.NewInt(1)))

	d := new(big.Int).Exp(e, big.NewInt(-1), phi)

	if d == nil {
		return
	}

	m := new(big.Int).Exp(c, d, n)

	mBytes := ResultChecker(strategy, m)

	if mBytes == nil {
		return
	}

	scriptPAndQAreEqual(n, e, c, mBytes)
}

func StrategyPAndQAreEqual(strategy *Strategy) {
	for _, n := range N {
		for _, e := range E {
			for _, c := range C {
				pAndQAreEqual(strategy, n, e, c)
			}
		}
	}
}
