package set2

import (
	"bytes"
	"crypto/aes"
	"fmt"
)

//challenge 9
func AddPKCS7Pad(raw []byte, lenBlock int) []byte {
	padLen := lenBlock - (len(raw) % lenBlock)
	var padding []byte
	padding = append(padding, byte(padLen))
	padding = bytes.Repeat(padding, padLen)
	raw = append(raw, padding...)
	return raw
}

func RemovePKCS7Pad(raw []byte, blockSize int) ([]byte, error) {
	var rawLen = len(raw)
	if rawLen%blockSize != 0 {
		return nil, fmt.Errorf("data's length isn't a multiple of blockSize")
	}
	padBlock := raw[rawLen-blockSize:]

	if ok, padLen := PaddingValidation(padBlock); ok {
		return raw[:rawLen-padLen], nil
	} else {
		return nil, fmt.Errorf("incorrect padding in last block")
	}
}

func PaddingValidation(block []byte) (bool, int) {
	padCharacter := block[len(block)-1]
	padSize := int(padCharacter)
	if padSize > aes.BlockSize || padSize == 0 {
		return false, 0
	}
	for i := len(block) - padSize; i < len(block); i++ {
		if block[i] != padCharacter {
			return false, 0
		}
	}
	return true, padSize
}
