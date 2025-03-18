package rsa

import (
	"math/big"
)

func init() {
	Strategies = append(Strategies, Strategy{
		Name: "p_and_q_are_equal",
		Func: StrategyPAndQAreEqual,
	})
}

func pAndQAreEqual(strategy *Strategy, n *big.Int, e *big.Int, c *big.Int) {
	p := new(big.Int).Sqrt(n)

	phi := new(big.Int).Mul(p, new(big.Int).Sub(p, big.NewInt(1)))

	d := new(big.Int).Exp(e, big.NewInt(-1), phi)

	if d == nil {
		return
	}

	m := new(big.Int).Exp(c, d, n)

	ResultChecker(strategy, m)
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
