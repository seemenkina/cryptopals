package set2

import (
	"fmt"
	"github.com/seemenkina/cryptopals/set1"
)

func CBCModeDecrypt(IV []byte, raw []byte, key []byte, size int) ([]byte, error) {
	prevBlock := IV
	var decrypted []byte
	for bs, be := 0, size; bs < len(raw); bs, be = bs+size, be+size {
		curBlock := raw[bs:be]
		encBlock, err := set1.AES128ECBDecrypt(key, curBlock)
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

func CBCModeEncrypt(IV []byte, raw []byte, key []byte, size int) ([]byte, error) {
	raw = AddPKCS7Pad(raw, size)
	prevBlock := IV
	var decrypted []byte
	for bs, be := 0, size; bs < len(raw); bs, be = bs+size, be+size {
		curBlock := raw[bs:be]
		block, _ := set1.XorBuffers(curBlock, prevBlock)
		encBlock, err := set1.AES128ECBEncrypt(key, block)
		if err != nil {
			return nil, fmt.Errorf("failed to use AES: %s", err)
		}
		decrypted = append(decrypted, encBlock...)
		prevBlock = encBlock
	}
	return decrypted, nil
}
