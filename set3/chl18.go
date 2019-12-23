package set3

import (
	"crypto/aes"
	"encoding/binary"
	"github.com/seemenkina/cryptopals/set1"
)

func CTRAES(key, plainText []byte, nonce int) ([]byte, error) {
	var cipherText []byte
	counterNonce := make([]byte, aes.BlockSize)
	counter := 0
	for bs, be := 0, aes.BlockSize; bs < len(plainText); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		binary.LittleEndian.PutUint64(counterNonce[:aes.BlockSize/2], uint64(nonce))
		binary.LittleEndian.PutUint64(counterNonce[aes.BlockSize/2:], uint64(counter))

		encCounter, err := set1.AES128ECBEncrypt(key, counterNonce)
		if err != nil {
			return nil, err
		}
		if be > len(plainText) {
			cBlock, err := set1.XorBuffers(plainText[bs:], encCounter)
			if err != nil {
				return nil, err
			}
			cipherText = append(cipherText, cBlock...)
			return cipherText, nil
		}
		cBlock, err := set1.XorBuffers(plainText[bs:be], encCounter)
		if err != nil {
			return nil, err
		}
		cipherText = append(cipherText, cBlock...)

		counter += 1
	}
	return cipherText, nil
}
