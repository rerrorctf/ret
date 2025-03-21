package rsa

import (
	"fmt"
	"math/big"
	"ret/theme"
	"sync"
	"time"
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

	StartTime time.Time
)

func ResultChecker(strategy *Strategy, m *big.Int) []byte {
	if strategy == nil {
		return nil
	}

	if m == nil {
		return nil
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
		return nil
	}

	now := time.Now()
	diff := now.Sub(StartTime)

	fmt.Printf("["+theme.ColorGreen+"%s"+theme.ColorReset+"] after %v\n🏁 "+theme.ColorPurple+"%s"+theme.ColorReset+"\n", strategy.Name, diff, mBytes)
	return mBytes
}

func Rsa() {
	StartTime = time.Now()

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
