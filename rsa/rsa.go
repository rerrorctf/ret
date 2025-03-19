package rsa

import (
	"fmt"
	"math/big"
	"sync"
)

type StrategyFunc func(*Strategy)

type Strategy struct {
	Name string
	Func StrategyFunc
}

var (
	P []*big.Int
	Q []*big.Int
	E []*big.Int
	D []*big.Int
	N []*big.Int
	C []*big.Int

	Strategies []Strategy
)

func ResultChecker(strategy *Strategy, m *big.Int) {
	if strategy == nil {
		return
	}

	if m == nil {
		return
	}

	mBytes := m.Bytes()
	ascii := true
	for _, b := range mBytes {
		if b < 0x20 || b > 0x7e {
			ascii = false
			break
		}
	}

	if ascii != true {
		return
	}

	fmt.Printf("[%s]\n%s\n", strategy.Name, mBytes)
}

func Rsa() {
	var strategyWG sync.WaitGroup

	for _, strategy := range Strategies {
		strategyWG.Add(1)

		go func() {
			defer strategyWG.Done()
			strategy.Func(&strategy)
		}()
	}

	strategyWG.Wait()
}
