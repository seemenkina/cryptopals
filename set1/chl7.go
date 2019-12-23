package set1

import (
	"crypto/aes"
	"fmt"
)

func AES128ECBDecrypt(key []byte, raw []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cipher; %s", err)
	}
	decrypted := make([]byte, len(raw))
	if len(raw)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("need a multiple of the blocksize for decrypt")
	}
	for bs, be := 0, aes.BlockSize; bs < len(raw); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		cipher.Decrypt(decrypted[bs:be], raw[bs:be])
	}
	return decrypted, nil
}

func AES128ECBEncrypt(key []byte, raw []byte) ([]byte, error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create new cipher; %s", err)
	}
	decrypted := make([]byte, len(raw))
	if len(raw)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("need a multiple of the blocksize for encrypt")
	}
	for bs, be := 0, aes.BlockSize; bs < len(raw); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		cipher.Encrypt(decrypted[bs:be], raw[bs:be])
	}
	return decrypted, nil
}
