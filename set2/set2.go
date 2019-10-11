package set2

import (
	"bytes"
	"fmt"
	"github.com/seemenkina/cryptopals/set1"
)

//challenge 9
func AddPKCS7Pad(raw []byte, lenBlock int) ([]byte, error) {
	padLen := lenBlock - (len(raw) % lenBlock)
	var padding []byte
	padding = append(padding, byte(padLen))
	padding = bytes.Repeat(padding, padLen)
	raw = append(raw, padding...)
	return raw, nil
}

func RemovePKCS7Pad(raw []byte, blockSize int) ([]byte, error) {
	var rawLen = len(raw)
	if rawLen%blockSize != 0 {
		return raw, fmt.Errorf("data's length isn't a multiple of blockSize")
	}
	padBlock := raw[rawLen-blockSize:]
	padCharacter := padBlock[blockSize-1]
	padSize := int(padCharacter)
	isPad := false

	for i := blockSize - padSize; i < blockSize; i++ {
		if padBlock[i] == padCharacter {
			isPad = true
		} else {
			isPad = false
		}
	}
	if isPad {
		return raw[:rawLen-padSize], nil
	} else {
		return raw, fmt.Errorf("incorrect padding in last block")
	}
}

//challenge 10
func Chall10(fileName string) ([]byte, error) {
	IV := bytes.Repeat([]byte("\x00"), 16)
	key := "YELLOW SUBMARINE"
	size := 16

	raw, err := set1.ReadBase64File(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %s", err)
	}

	raw, err = CBCMode(IV, raw, []byte(key), size)
	if err != nil {
		return nil, fmt.Errorf("faliled to use AES in CBC mode: %s", err)
	}

	return raw, nil
}

func CBCMode(IV []byte, raw []byte, key []byte, size int) ([]byte, error) {
	prevBlock := IV
	var decrypted []byte
	for bs, be := 0, size; bs < len(raw); bs, be = bs+size, be+size {
		curBlock := raw[bs:be]
		encBlock, err := set1.AES128ECB(key, curBlock)
		block, _ := set1.XorBuffers(encBlock, prevBlock)
		if err != nil {
			return nil, fmt.Errorf("failed to use AES: %s", err)
		}
		decrypted = append(decrypted, block...)
		prevBlock = curBlock
	}

	decrypted, err := RemovePKCS7Pad(decrypted, size)
	if err != nil {
		return nil, fmt.Errorf("failed to remove padding in data: %s", err)
	}
	return decrypted, nil
}
