package set1

import (
	"fmt"
	"math/bits"
)

func BreakingRepeatingKeyXor(raw []byte) ([]byte, []byte, error) {
	keySize, err := FindKeySize(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to detect size of key: %s", err)
	}

	blocks := make([][]byte, keySize)
	for i := 0; i < len(raw); i++ {
		blocks[i%keySize] = append(blocks[i%keySize], raw[i])
	}

	var totKey []byte
	for i := 0; i < keySize; i++ {
		_, key, _ := BruteSingleXor(blocks[i])
		totKey = append(totKey, key)
	}

	totRaw, err := RepeatingKeyXor(totKey, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt by repeating-key xor cipher: %s", err)
	}

	return totRaw, totKey, nil
}

func HammingDistance(s1, s2 []byte) (int, error) {
	if len(s1) != len(s2) {
		return -1, fmt.Errorf("length of compare's strings must be equal")
	}
	distance := 0
	for i := 0; i < len(s1); i++ {
		distance += bits.OnesCount(uint(s1[i] ^ s2[i]))
	}
	return distance, nil
}

func FindKeySize(buffer []byte) (int, error) {
	var minDistance float64
	var keySize int

	const blockNum = 4
	for size := 2; size < 41; size++ {

		bufBytes := buffer[:size*blockNum]

		var blockByte [][]byte
		for i := 0; i < blockNum; i++ {
			block := bufBytes[i*size : (i+1)*size]
			blockByte = append(blockByte, block)
		}

		sumDist := 0
		sum := 0
		for j := 0; j < blockNum; j++ {
			for i := j + 1; i < blockNum; i++ {
				curDistance, _ := HammingDistance(blockByte[j], blockByte[i])
				sumDist += curDistance
				sum++
			}
		}

		normCurDistance := float64(sumDist) / float64(sum) / float64(size)

		if size == 2 {
			minDistance = normCurDistance
			keySize = size
		}
		if normCurDistance < minDistance {
			minDistance = normCurDistance
			keySize = size
		}
	}
	return keySize, nil
}
