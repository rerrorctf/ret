package util

import (
	"fmt"
	"math/big"
	"ret/theme"
	"strings"
)

func LooksLikeBase16(arg string) bool {
	for _, c := range arg {
		if c > rune('9') {
			return true
		}
	}

	return false
}

func ParseBigInt(arg string) *big.Int {
	if LooksLikeBase16(arg) {
		if strings.HasPrefix(arg, "0x") || strings.HasPrefix(arg, "0X") {
			arg = arg[2:]
		}

		X, _ := new(big.Int).SetString(arg, 16)
		return X
	}

	X, _ := new(big.Int).SetString(arg, 10)
	return X
}

func ParseBigInts(XS *[]*big.Int, arg string) {
	xs := strings.Split(arg, ",")
	for _, x := range xs {
		X := ParseBigInt(x)
		if X == nil {
			fmt.Printf("😰"+theme.ColorGray+" \""+theme.ColorReset+"%v"+theme.ColorGray+"\""+theme.ColorRed+
				" could not be parsed"+theme.ColorReset+"\n", x)
			continue
		}

		*XS = append(*XS, X)
	}
}
