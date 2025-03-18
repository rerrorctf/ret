package rsa

import (
	"fmt"
	"math/big"
)

var (
	P []*big.Int
	Q []*big.Int
	E []*big.Int
	D []*big.Int
	N []*big.Int
	C []*big.Int
)

func Rsa() {
	fmt.Printf("%v %v %v %v %v %v\n", P, Q, E, D, N, C)
}
