package set2

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/davecgh/go-spew/spew"
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
	const key = "YELLOW SUBMARINE"
	const size = 16

	raw, err := set1.ReadBase64File(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %s", err)
	}

	raw, err = CBCModeDecrypt(IV, raw, []byte(key), size)
	if err != nil {
		return nil, fmt.Errorf("faliled to use AES in CBC mode: %s", err)
	}

	return raw, nil
}

func CBCModeDecrypt(IV []byte, raw []byte, key []byte, size int) ([]byte, error) {
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

func CBCModeEncrypt(IV []byte, raw []byte, key []byte, size int) ([]byte, error) {

	raw, err := AddPKCS7Pad(raw, size)
	if err != nil {
		return nil, fmt.Errorf("failed to add padding in data: %s", err)
	}

	prevBlock := IV
	var decrypted []byte
	for bs, be := 0, size; bs < len(raw); bs, be = bs+size, be+size {
		curBlock := raw[bs:be]
		block, _ := set1.XorBuffers(curBlock, prevBlock)
		encBlock, err := set1.AES128ECB(key, block)
		if err != nil {
			return nil, fmt.Errorf("failed to use AES: %s", err)
		}
		decrypted = append(decrypted, encBlock...)
		prevBlock = encBlock
	}
	return decrypted, nil
}

func GenerateRandBytes(size int) ([]byte, error) {
	raw := make([]byte, size)
	_, err := rand.Read(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random byte: %s", err)
	}
	return raw, nil
}

func AddBytes2Text(input []byte) ([]byte, error) {
	var prefixSize = len(input)%10 + 5
	var suffixSize = len(input)%10 + 5
	prefix, err := GenerateRandBytes(prefixSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate prefix: %s", err)
	}
	suffix, err := GenerateRandBytes(suffixSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sufix: %s", err)
	}

	var plainText []byte
	plainText = append(prefix, input...)
	plainText = append(plainText, suffix...)

	return plainText, nil
}

type functionOracle func([]byte) ([]byte, error)

func EncryptionOracle(input []byte) ([]byte, error) {
	const keySize = 16
	key, err := GenerateRandBytes(keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %s", err)
	}

	plainText, err := AddBytes2Text(input)
	if err != nil {
		return nil, fmt.Errorf("failed to add random bytes for text: %s", err)
	}

	plainText, err = AddPKCS7Pad(plainText, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to add padding: %s", err)
	}

	const randByteSize = 1
	sb, err := GenerateRandBytes(randByteSize)
	var encrypted []byte
	if sb[0]%2 == 0 {
		fmt.Print("ECB ")
		encrypted, err = set1.AES128ECB(key, plainText)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt: %s", err)
		}
	} else {
		fmt.Print("CBC ")
		IV, err := GenerateRandBytes(keySize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate IV: %s", err)
		}
		encrypted, err = CBCModeEncrypt(IV, plainText, key, keySize)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt: %s", err)
		}
	}
	return encrypted, nil
}

func BlackBox(oracle functionOracle) {
	const size = 64
	input := make([]byte, size)
	for i := 0; i < 20; i++ {
		out, _ := oracle(input)
		if set1.HasRepeatedBlock(out) {
			fmt.Println("ECB")
		} else {
			fmt.Println("CBC")
		}
	}
}

func Chl12() []byte {
	const key = "6e666eccf758c5386fb3b444ba61c362"
	const unknownStr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lyb" +
		"GllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unkRaw, _ := base64.StdEncoding.DecodeString(string(unknownStr))
	encr, _ := ByteAtTimeECBDetect(unkRaw, []byte(key))
	return encr
}

func ByteAtTimeECBDetect(secret []byte, randKey []byte) ([]byte, error) {
	var suf = []byte("A")
	var input []byte
	for i := 0; i < 16; i++ {
		suf = append(suf, []byte("A")...)
		input = append(suf, secret...)
		if len(input)%16 == 0 {
			println(len(input) / 16)
			break
		}
	}
	input, _ = AddPKCS7Pad(input, 16)
	encr, _ := set1.AES128ECB(randKey, input)
	if set1.HasRepeatedBlock(encr) {
		fmt.Println("ECB")
	}
	spew.Dump(encr)
	return encr, nil
}
