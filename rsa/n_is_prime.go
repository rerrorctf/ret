package rsa

import (
	"fmt"
	"math/big"
)

func init() {
	Strategies = append(Strategies, Strategy{
		Name: "n_is_prime",
		Func: StrategyNIsPrime,
	})
}

func scriptNIsPrime(n *big.Int, e *big.Int, c *big.Int, mBytes []byte) {
	fmt.Printf(
		"\n```python\n"+
			"#!/usr/bin/env python3\n\n"+
			"n = %s\n"+
			"e = %s\n"+
			"c = %s\n\n"+
			"phi = n - 1\n"+
			"d = pow(e, -1, phi)\n"+
			"m = pow(c, d, n)\n\n"+
			"flag = m.to_bytes(length=(m.bit_length() + 7) // 8, byteorder=\"big\")\n"+
			"print(flag.decode()) # %s\n```\n",
		n, e, c, mBytes)
}

func nIsPrime(strategy *Strategy, n *big.Int, e *big.Int, c *big.Int) {
	phi := new(big.Int).Sub(n, big.NewInt(1))

	d := new(big.Int).Exp(e, big.NewInt(-1), phi)
	if d == nil {
		return
	}

	m := new(big.Int).Exp(c, d, n)

	mBytes := ResultChecker(strategy, m)

	if mBytes == nil {
		return
	}

	scriptNIsPrime(n, e, c, mBytes)
}

func StrategyNIsPrime(strategy *Strategy) {
	for _, n := range N {
		for _, e := range E {
			for _, c := range C {
				nIsPrime(strategy, n, e, c)
			}
		}
	}
}
