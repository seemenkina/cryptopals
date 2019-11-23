package set3

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"github.com/davecgh/go-spew/spew"
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

func (as *AESStruct) Oracle(cipher []byte, iv []byte) bool {
	msg, err := set2.CBCModeDecrypt(iv, cipher, as.key, aes.BlockSize)
	spew.Dump("msg")
	spew.Dump(msg)
	if err != nil {
		return false
	} else {
		return true
	}
}

func (as *AESStruct) PaddingOracleAttack(msg []byte, iv []byte) []byte {
	prevBlock := iv
	var plainText []byte
	for bs, be := 0, aes.BlockSize; bs < len(msg); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		plainBlock := make([]byte, aes.BlockSize)
		atBlock := make([]byte, aes.BlockSize)
		_, _ = rand.Read(atBlock)
		for i := aes.BlockSize - 1; i >= 0; i-- {
			for j := 0; j < 256; j++ {
				atBlock[i] = byte(j)
				chMsg := bytes.Replace(msg, msg[bs:be], atBlock, aes.BlockSize)
				if as.Oracle(chMsg, iv) {
					plainBlock[i] = atBlock[i] ^ byte(aes.BlockSize-i+1) ^ prevBlock[i]
					break
				}
			}
		}
		plainText = append(plainText, plainBlock...)
	}
	return plainText
}

func (as *AESStruct) PadLen(msg, iv []byte) {
	//msgcop := msg
	spew.Dump(msg)
	for bs, be := 0, aes.BlockSize; bs < len(msg); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		spew.Dump("new block")
		spew.Dump(msg[bs:be])
		for i := 0; i < aes.BlockSize; i++ {
			curBlock := msg[bs:be]
			curBlock[i] = byte(0x0)
			msgcop := bytes.Replace(msg, msg[bs:be], curBlock, -1)
			if !as.Oracle(msgcop, iv) {
				spew.Dump(i)
				break
			}
		}
	}
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
