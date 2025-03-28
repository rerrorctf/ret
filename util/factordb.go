package util

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
)

func FactorDB(n *big.Int) ([]*big.Int, string, error) {
	url := fmt.Sprintf("https://factordb.com/api/?query=%s", n)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}

	type FactorDBResult struct {
		Status string `json:"status"`
	}

	var result FactorDBResult
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, "", err
	}

	if result.Status != "FF" {
		return nil, "", nil
	}

	type FactorDBFFResult struct {
		Status  string          `json:"status"`
		Factors [][]interface{} `json:"factors"`
	}

	var ffResult FactorDBFFResult
	if err := json.Unmarshal(body, &ffResult); err != nil {
		return nil, "", err
	}

	if len(ffResult.Factors) < 2 {
		return nil, "", nil
	}

	if len(ffResult.Factors[0]) < 1 {
		return nil, "", nil
	}

	factors := make([]*big.Int, 0)

	for _, factor := range ffResult.Factors {
		fs, _ := factor[0].(string)
		f, _ := new(big.Int).SetString(fs, 10)
		c, _ := factor[1].(float64)

		for range int64(c) {
			factors = append(factors, f)
		}
	}

	return factors, url, nil
}
