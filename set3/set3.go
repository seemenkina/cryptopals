package set3

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"github.com/seemenkina/cryptopals/set1"
	"github.com/seemenkina/cryptopals/set2"
)

type AESStruct struct {
	key []byte
}

func (as *AESStruct) Encrypt(msg []byte) ([]byte, []byte) {
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)

	decr, err := set2.CBCModeEncrypt(iv, msg, as.key, aes.BlockSize)
	if err != nil {
		panic(err)
	}
	return decr, iv
}

func (as *AESStruct) Oracle(iv []byte, cipher []byte) bool {
	_, err := set2.CBCModeDecrypt(iv, cipher, as.key, aes.BlockSize)
	if err != nil {
		return false
	} else {
		return true
	}
}

func (as *AESStruct) PaddingOracleAttack(msg []byte, iv []byte) []byte {
	var plainText []byte
	msg = append(iv, msg...)
	for bs, be := len(msg)-aes.BlockSize, len(msg); bs >= aes.BlockSize; bs, be = bs-aes.BlockSize, be-aes.BlockSize {
		prevBlock := msg[bs-aes.BlockSize : be-aes.BlockSize]
		curBlock := msg[bs:be]
		var interBlock []byte

		for i := aes.BlockSize - 1; i >= 0; i-- {
			prefix := make([]byte, i)
			_, _ = rand.Read(prefix)

			var padding []byte
			for k := 0; k < len(interBlock); k++ {
				padding = append(padding, byte(aes.BlockSize-i)^interBlock[k])
			}

			var chr byte
			for j := 0; j < 256; j++ {
				var atBlock []byte
				atBlock = append(prefix, byte(j))
				atBlock = append(atBlock, padding...)
				if as.Oracle(atBlock, curBlock) {
					chr = byte(j)
					break
				}
			}
			var s []byte
			s = append(s, chr^byte(aes.BlockSize-i))
			interBlock = append(s, interBlock...)

			var plainBlock []byte

			plainBlock = append(plainBlock, interBlock[0]^prevBlock[i])
			plainText = append(plainBlock, plainText...)
		}
	}
	plainText, _ = set2.RemovePKCS7Pad(plainText, aes.BlockSize)
	return plainText
}

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
