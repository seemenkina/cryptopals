package set1

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"

	//"math"
	"os"
)

//challenge 1 - convert hex to base64
func HexToBase64(input string) (string, error) {
	raw, err := hex.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex: %s", err)
	}
	out := base64.StdEncoding.EncodeToString(raw)
	return out, nil
}

//challenge2 - Write a function that takes two equal-length buffers and produces their XOR combination.
func XorBuffers(raw1, raw2 []byte) ([]byte, error) {
	xorBuf := make([]byte, len(raw1))
	for i := 0; i < len(raw1); i++ {
		xorBuf[i] = raw1[i] ^ raw2[i]
	}
	return xorBuf, nil
}

//challenge 3 -
func Chl3BruteSingleXor(raw []byte) ([]byte, error) {
	rightRaw, _, _ := bruteSingleXor(raw)
	return rightRaw, nil
}

func bruteSingleXor(raw []byte) ([]byte, byte, float64) {
	rightRaw := make([]byte, len(raw))
	var rightKey byte
	totalWeight := 0.0

	for i := 1; i < 256; i++ {
		xorRaw := xorSingleByte(raw, byte(i))
		curWeight := 0.0
		curWeight = textWeight(xorRaw)
		if curWeight > totalWeight {
			totalWeight = curWeight
			rightKey = byte(i)
			rightRaw = xorRaw
		}
	}
	return rightRaw, rightKey, totalWeight
}

func xorSingleByte(raw []byte, singleByte byte) []byte {
	xorRaw := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		xorRaw[i] = raw[i] ^ singleByte
	}
	return xorRaw
}

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

//challenge 4
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
		curRaw, _, curWeight := bruteSingleXor(raw)
		if curWeight > totalWeight {
			totalWeight = curWeight
			rightRaw = curRaw
		}
	}
	return rightRaw, nil
}

//challenge 5
func RepeatingKeyXor(key []byte, input []byte) ([]byte, error) {
	xorRaw := make([]byte, len(input))

	for i := 0; i < len(input); i++ {
		xorRaw[i] = input[i] ^ key[i%len(key)]
	}
	return xorRaw, nil
}

//challenge 6
func Chl6(fileName string) ([]byte, []byte, error) {
	decoded, err := ReadBase64File(fileName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file: %s", err)
	}
	raw, key, err := BreakingRepeatingKeyXor(decoded)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to break repeating-key xor cipher: %s", err)
	}
	return raw, key, nil
}

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
		_, key, _ := bruteSingleXor(blocks[i])
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
		distance += dist(s1[i], s2[i])
	}
	return distance, nil
}

func dist(x, y byte) int {
	var r int
	x ^= y
	for x != 0 {
		r++
		x &= x - 1
	}
	return r
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

func ReadBase64File(fileName string) ([]byte, error) {
	buffer, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read file; %s", err)
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(buffer)))
	n, err := base64.StdEncoding.Decode(decoded, buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to decode file; %s", err)
	}

	return decoded[:n], nil
}

//challenge 7
func Chl7AES128ECB(fileName string) ([]byte, error) {
	raw, err := ReadBase64File(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read file; %s", err)
	}

	key := "YELLOW SUBMARINE"
	decode, err := AES128ECB([]byte(key), raw)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file; %s", err)
	}
	return decode, nil
}

func AES128ECB(key []byte, raw []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cipher; %s", err)
	}
	decrypted := make([]byte, len(raw))
	size := 16
	for bs, be := 0, size; bs < len(raw); bs, be = bs+size, be+size {
		cipher.Decrypt(decrypted[bs:be], raw[bs:be])
	}

	return decrypted, nil
}

//challenge 8
func Chl8AES128ECB(fileName string) (string, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return "", fmt.Errorf("failed to open file; %s", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var rightRaw []byte

	for scanner.Scan() {
		line := scanner.Text()
		lineDecode, err := hex.DecodeString(line)
		if err != nil {
			return "", fmt.Errorf("failed to decode line; %s", err)
		}
		if hasRepeatedBlock(lineDecode) {
			rightRaw = lineDecode
		}
	}
	hexRightRaw := hex.EncodeToString(rightRaw)
	return hexRightRaw, nil

}

func hasRepeatedBlock(data []byte) bool {
	blockSize := 16
	blockCount := len(data) / blockSize
	blocks := make([][]byte, blockCount)
	for i := 0; i < blockCount; i++ {
		blocks[i] = data[i*blockSize : (i+1)*blockSize]
	}

	for i := 0; i < blockCount; i++ {
		for j := i + 1; j < blockCount; j++ {
			if bytes.Equal(blocks[i], blocks[j]) {
				return true
			}
		}
	}
	return false
}
