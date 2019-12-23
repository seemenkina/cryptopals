package set2

import (
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"github.com/seemenkina/cryptopals/set1"
)

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
	const keySize = aes.BlockSize
	key, err := GenerateRandBytes(keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %s", err)
	}

	plainText, err := AddBytes2Text(input)
	if err != nil {
		return nil, fmt.Errorf("failed to add random bytes for text: %s", err)
	}

	plainText = AddPKCS7Pad(plainText, keySize)

	const randByteSize = 1
	sb, err := GenerateRandBytes(randByteSize)
	var encrypted []byte
	if sb[0]%2 == 0 {
		fmt.Print("ECB ")
		encrypted, err = set1.AES128ECBDecrypt(key, plainText)
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
