package rsa

import (
	"fmt"
	"math/big"
	"sync"
)

var (
	n0 = big.NewInt(0)
	n2 = big.NewInt(2)
	n3 = big.NewInt(3)
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
			"print(flag.decode()) # %s\n```\n\n",
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
			"print(flag.decode()) # %s\n```\n\n",
		n, c, k, mBytes)
}

func computeCubeRoot(y *big.Int) (*big.Int, bool) {
	// based on https://github.com/chfast/mini-gmp/blob/95c194c8b1a475939d9fa29ff6b9a30b71dcbf48/mini-gmp/mini-gmp.c#L3216

	u := big.NewInt(0)
	t := big.NewInt(0)
	v := big.NewInt(0)
	tmp := big.NewInt(0)

	t.SetBit(t, y.BitLen()/3+1, 1)

	for {
		tmp.Set(u)
		u.Set(t)
		t.Set(tmp)

		t.Exp(u, n2, nil)
		t.Div(y, t)
		v.Mul(u, n2)
		t.Add(t, v)
		t.Div(t, n3)

		if t.Cmp(u) >= 0 {
			break
		}
	}

	t.Exp(u, n3, nil)
	v.Sub(y, t)

	exact := v.Cmp(n0) == 0

	return u, exact
}

func StrategyCubeRoot(strategy *Strategy) {
	var wg sync.WaitGroup

	for _, c := range C {
		m, exact := computeCubeRoot(c)

		if exact {
			mBytes := ResultChecker(strategy, m)

			if mBytes != nil {
				scriptCubeRootExact(c, mBytes)
				continue
			}
		}

		for _, n := range N {
			wg.Add(1)

			go func() {
				defer wg.Done()

				for k := 0; k < 100000000; k++ {
					newC := new(big.Int).Add(c, new(big.Int).Mul(big.NewInt(int64(k)), n))
					m, exact := computeCubeRoot(newC)

					if !exact {
						continue
					}

					mBytes := ResultChecker(strategy, m)

					if mBytes == nil {
						continue
					}

					scriptCubeRootCoefficient(n, c, k, mBytes)
					break
				}
			}()
		}
	}

	wg.Wait()
}

// examples:
// n = 21507386633439519550169998646896627263990342978145866337442653437291500212804540039826669967421406761783804525632864075787433199834243745244830254423626433057121784913173342863755047712719972310827106310978325541157116399004997956022957497614561358547338887866829687642469922480325337783646738698964794799137629074290136943475809453339879850896418933264952741717996251598299033247598332283374311388548417533241578128405412876297518744631221434811566527970724653020096586968674253730535704100196440896139791213814925799933321426996992353761056678153980682453131865332141631387947508055668987573690117314953760510812159,
// e = 3,
// c = 6723702102195566573155033480869753489283107574855029844328060266358539778148984297827300182772738267875181687326892460074882512254133616280539109646843128644207390959955541800567609034853,
//
// k = 6410662
// c = 41371441628678749855341069318913940139183366190092850457791401944637484881722387130432528789403867120983310612023037050412981687401539375118177921234958241549652642148049464476777138721957300380163011255302922062871368980358844918698066643476906429304993326666393192819367202508911333287188748033044647
// e = 3
// n = 125533848452137763185016834412259349043987425043688722410453579918645013940088212764269073831951730407180201649381111989694930753816422349270797992511026080967667823475550286796327579680655909172631694714891168782703472181155691095137469432249992072921349964218538827606766136606019411932023475455088911
