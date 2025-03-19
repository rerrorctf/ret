package rsa

import (
	"fmt"
	"math/big"
)

func init() {
	Strategies = append(Strategies, Strategy{
		Name: "cube_root",
		Func: StrategyCubeRoot,
	})
}

func scriptCubeRootExact(c *big.Int, mBytes []byte) {
	fmt.Printf(
		"\n```python\n"+
			"#!/usr/bin/env python3\n\n"+
			"def cube_root(x):\n"+
			"    lo = 1\n"+
			"    hi = x\n"+
			"    while lo < hi:\n"+
			"        mid = (lo + hi) // 2\n"+
			"        if (mid * mid * mid) < x:\n"+
			"            lo = mid + 1\n"+
			"        else:\n"+
			"            hi = mid\n"+
			"    return lo\n\n"+
			"c = %s\n\n"+
			"m = cube_root(c)\n"+
			"flag = m.to_bytes(length=(m.bit_length() + 7) // 8, byteorder=\"big\")\n"+
			"print(flag.decode()) # %s\n```\n",
		c, mBytes)
}

func scriptCubeRootCoefficient(n *big.Int, c *big.Int, k int, mBytes []byte) {
	fmt.Printf(
		"\n```python\n"+
			"#!/usr/bin/env python3\n\n"+
			"import gmpy2\n\n"+
			"n = %s\n"+
			"c = %s\n\n"+
			"k = 0\n"+
			"while (gmpy2.iroot(c + k * n, 3)[1] == False):\n"+
			"    k += 1\n"+
			"m = gmpy2.iroot(c + k * n, 3)[0] # k = %v\n\n"+
			"flag = m.to_bytes(length=(m.bit_length() + 7) // 8, byteorder=\"big\")\n"+
			"print(flag.decode()) # %s\n```\n",
		n, c, k, mBytes)
}

func computeCubeRoot(x *big.Int) (*big.Int, bool) {
	lo := big.NewInt(1)
	hi := new(big.Int).Set(x)
	var mid, tmp big.Int

	for lo.Cmp(hi) < 0 {
		mid.Add(lo, hi)
		mid.Rsh(&mid, 1)

		tmp.Mul(&mid, &mid)
		tmp.Mul(&tmp, &mid)

		switch tmp.Cmp(x) {
		case -1:
			lo.Add(&mid, big.NewInt(1))
		case 0, 1:
			hi.Set(&mid)
		}
	}

	exact := false
	y := new(big.Int).Exp(lo, big.NewInt(3), nil)

	if x.Cmp(y) == 0 {
		exact = true
	}

	return lo, exact
}

func cubeRoot(strategy *Strategy, c *big.Int, n *big.Int) {
	m, exact := computeCubeRoot(c)

	if exact {
		mBytes := ResultChecker(strategy, m)

		if mBytes != nil {
			scriptCubeRootExact(c, mBytes)
			return
		}
	}

	for k := 0; k < 10000; k++ {
		newC := new(big.Int).Add(c, new(big.Int).Mul(big.NewInt(int64(k)), n))
		m, exact = computeCubeRoot(newC)

		if !exact {
			continue
		}

		mBytes := ResultChecker(strategy, m)

		if mBytes == nil {
			return
		}

		scriptCubeRootCoefficient(n, c, k, mBytes)
		break
	}
}

func StrategyCubeRoot(strategy *Strategy) {
	for _, n := range N {
		for _, c := range C {
			cubeRoot(strategy, c, n)
		}
	}
}
