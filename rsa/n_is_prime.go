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

// examples:
// n = 128393532851463575343089974408848099857979358442919384244000744053339479654557691794114605827105884545240515605112453686433508264824840575897640756564360373615937755743038201363814617682765101064651503434978938431452409293245855062934837618374997956788830791719002612108253528457601645424542240025303582528541
// e = 65537
// c = 93825584976187667358623690800406736193433562907249950376378278056949067505651948206582798483662803340120930066298960547657544217987827103350739742039606274017391266985269135268995550801742990600381727708443998391878164259416326775952210229572031793998878110937636005712923166229535455282012242471666332812788
