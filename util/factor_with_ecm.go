package util

import (
	"bufio"
	"fmt"
	"math/big"
	"os/exec"
	"ret/theme"
	"strings"
)

func CheckIfECMInstalled() bool {
	cmd := exec.Command("/usr/bin/ecm", "--help")

	err := cmd.Run()
	if err != nil {
		fmt.Printf("😰"+theme.ColorGray+" \""+theme.ColorReset+"%v"+theme.ColorGray+"\""+theme.ColorYellow+
			" failed"+theme.ColorReset+"! consider installing "+theme.ColorCyan+"gmp-ecm"+theme.ColorReset+"\n\n", cmd.String())
		return false
	}

	return true
}

func FactorWithECM(n *big.Int) ([]*big.Int, string, error) {
	cmd := exec.Command("/usr/bin/ecm", "-c", "1000000000", "-one", "2000")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, cmd.String(), err
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, cmd.String(), err
	}

	factors := make([]*big.Int, 0)

	cofactor := new(big.Int).Set(n)

	stdin.Write([]byte(fmt.Sprintf("%s\n", cofactor)))

	cmd.Start()

	scanner := bufio.NewScanner(stdout)

	for scanner.Scan() {
		line := scanner.Text()

		splits := strings.Split(line, " ")

		if strings.Contains(line, "Found prime factor of ") {
			factor, _ := new(big.Int).SetString(splits[len(splits)-1], 10)
			factors = append(factors, factor)
			continue
		}

		if strings.Contains(line, "Composite cofactor") {
			cofactor.SetString(splits[2], 10)
			stdin.Write([]byte(fmt.Sprintf("%s\n", cofactor)))
			continue
		}

		if strings.Contains(line, "Prime cofactor") {
			factor, _ := new(big.Int).SetString(splits[2], 10)
			factors = append(factors, factor)
			break
		}
	}

	return factors, cmd.String(), nil
}
