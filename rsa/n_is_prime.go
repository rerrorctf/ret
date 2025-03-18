package rsa

import (
	"math/big"
)

func init() {
	Strategies = append(Strategies, Strategy{
		Name: "n_is_prime",
		Func: StrategyNIsPrime,
	})
}

func nIsPrime(strategy *Strategy, n *big.Int, e *big.Int, c *big.Int) {
	phi := new(big.Int).Sub(n, big.NewInt(1))

	d := new(big.Int).Exp(e, big.NewInt(-1), phi)
	if d == nil {
		return
	}

	m := new(big.Int).Exp(c, d, n)

	ResultChecker(strategy, m)
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
