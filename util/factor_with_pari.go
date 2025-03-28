package util

import (
	"bufio"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"ret/theme"
	"strconv"
	"strings"
)

func CheckIfPariInstalled() bool {
	cmd := exec.Command("/usr/bin/gp", "-v")

	err := cmd.Run()
	if err != nil {
		fmt.Printf("😰"+theme.ColorGray+" \""+theme.ColorReset+"%v"+theme.ColorGray+"\""+theme.ColorYellow+
			" failed"+theme.ColorReset+"! consider installing "+theme.ColorCyan+"pari-gp"+theme.ColorReset+"\n", cmd.String())
		return false
	}

	return true
}

func FactorWithPari(n *big.Int) ([]*big.Int, string, error) {

	file, err := os.CreateTemp("", "ret_rsa_factorme")

	fmt.Fprintf(file, "print(factorint(%s))\n", n)

	file.Close()

	cmd := exec.Command("/usr/bin/gp", "--stacksize", "1073741824", "--fast", "--quiet", file.Name())

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, cmd.String(), err
	}

	factors := make([]*big.Int, 0)

	cmd.Start()

	scanner := bufio.NewScanner(stdout)

	if !scanner.Scan() {
		return nil, cmd.String(), err
	}

	line := scanner.Text()
	splits := strings.Split(line[1:len(line)-1], ";")

	for _, split := range splits {
		nums := strings.Split(split, ",")

		count, err := strconv.Atoi(strings.TrimSpace(nums[1]))
		if err != nil {
			return nil, cmd.String(), err
		}

		factor, _ := new(big.Int).SetString(strings.TrimSpace(nums[0]), 10)

		for range count {
			factors = append(factors, factor)
		}
	}

	return factors, cmd.String(), nil
}
