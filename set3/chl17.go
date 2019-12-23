package set3

import (
	"crypto/aes"
	"crypto/rand"
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
