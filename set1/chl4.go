package set1

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
)

func textWeight(raw []byte) float64 {
	mapFreq := map[string]float64{
		"e": 12.02, "t": 9.10, "a": 8.12, "i": 7.31, "n": 6.95, "o": 7.68, "s": 6.28, "h": 5.92, "r": 6.02,
		"d": 4.32, "l": 3.98, "u": 2.88, "c": 2.71, "m": 2.61, "f": 2.30, "w": 2.09, "y": 2.11, "g": 2.03,
		"p": 1.82, "b": 1.49, "v": 1.11, "k": 0.69, "q": 0.11, "j": 0.10, "x": 0.17, "z": 0.07, " ": 6.40,
	}
	weight := 0.0

	for i := 0; i < len(raw); i++ {
		if val, ok := mapFreq[string(raw[i])]; ok {
			weight += val
		}
	}
	return weight
}

//challenge 4 - detect single character xor
func FindSingleXorKey(fileName string) ([]byte, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %s", err)
	}
	defer file.Close()

	totalWeight := 0.0
	scanner := bufio.NewScanner(file)
	var rightRaw []byte

	for scanner.Scan() {
		line := scanner.Text()
		raw, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex: %s", err)
		}
		curRaw, _, curWeight := BruteSingleXor(raw)
		if curWeight > totalWeight {
			totalWeight = curWeight
			rightRaw = curRaw
		}
	}
	return rightRaw, nil
}
