package set3

import (
	"fmt"

	"github.com/seemenkina/cryptopals/set1"
)

// DONE - first part each text
// DO - end of the text
func (as *AESStruct) FixedNonceCTRAttackStatistically(ciphers [][]byte, nonce int) [][]byte {
	var minLen = len(ciphers[0])
	var plainText = make([][]byte, len(ciphers))
	// for j := 0; j < len(ciphers); j++ {
	counts := 0
	for i := 0; i < len(ciphers); i++ {
		if len(ciphers[i]) == 0 {
			counts += 1
		} else if len(ciphers[i]) <= minLen && len(ciphers[i]) != 0 {
			minLen = len(ciphers[i])
		}
	}
	if counts == len(ciphers) {
		return plainText
	}

	for i := 0; i < len(ciphers); i++ {
		if len(ciphers[i]) == 0 {
			ciphers = append(ciphers[:i], ciphers[i+1:]...)
		}
	}

	var xorText []byte
	uniformCiphers := make([][]byte, len(ciphers))
	for i := 0; i < len(ciphers); i++ {
		if len(ciphers[i]) != 0 {
			uniformCiphers[i] = ciphers[i][:minLen]
			// ciphers[i] = ciphers[i][minLen:]
			xorText = append(xorText, uniformCiphers[i]...)
		}
	}
	// for i:=0; i < len(ciphers); i++ {
	//	fmt.Printf("%x\n", ciphers[i])
	// }

	raw, err := BreakingRepeatingKeyXor(xorText, minLen)
	if err != nil {
		panic(err)
	}

	for i := 0; i < len(ciphers); i++ {
		if len(ciphers[i]) != 0 {
			if (i+1)*minLen >= len(raw) {
				plainText[i] = append(plainText[i], raw[i*minLen:]...)
			} else {
				plainText[i] = append(plainText[i], raw[i*minLen:(i+1)*minLen]...)
			}
		}
	}
	// }

	return plainText
}

func BreakingRepeatingKeyXor(raw []byte, keySize int) ([]byte, error) {
	blocks := make([][]byte, keySize)
	for i := 0; i < len(raw); i++ {
		blocks[i%keySize] = append(blocks[i%keySize], raw[i])
	}

	var totKey []byte
	for i := 0; i < keySize; i++ {
		_, key, _ := BruteSingleXor(blocks[i])
		totKey = append(totKey, key)
	}

	totRaw, err := set1.RepeatingKeyXor(totKey, raw)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt by repeating-key xor cipher: %s", err)
	}

	return totRaw, nil
}

func BruteSingleXor(raw []byte) ([]byte, byte, int) {
	rightRaw := make([]byte, len(raw))
	var rightKey byte
	totalWeight := 0

	for i := 1; i < 256; i++ {
		xorRaw := set1.XorSingleByte(raw, byte(i))
		curWeight := 0
		for j := 0; j < len(xorRaw); j++ {
			if int(xorRaw[j]) >= 92 && int(xorRaw[j]) <= 122 || int(xorRaw[j]) == 32 || int(xorRaw[j]) >= 65 && int(xorRaw[j]) <= 90 {
				curWeight += int(xorRaw[j])
			}
		}
		if curWeight > totalWeight {
			totalWeight = curWeight
			rightKey = byte(i)
			rightRaw = xorRaw
		}
	}
	return rightRaw, rightKey, totalWeight
}
