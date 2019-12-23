package set2

import (
	"crypto/aes"
	"strings"
)

type CBCModule struct {
	IV  []byte
	key []byte
}

func (cm *CBCModule) createUserStr(userData []byte) ([]byte, error) {
	userStr := string(userData)

	pad := "comment1=cooking%20MCs;userdata="
	suf := ";comment2=%20like%20a%20pound%20of%20bacon"

	userStr = strings.ReplaceAll(userStr, ";", "?")
	userStr = strings.ReplaceAll(userStr, "=", "?")

	encr, err := CBCModeEncrypt(cm.IV, []byte(pad+userStr+suf), cm.key, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return encr, nil
}

func (cm *CBCModule) isConsistStr(cipherT []byte) bool {
	decr, err := CBCModeDecrypt(cm.IV, cipherT, cm.key, aes.BlockSize)
	if err != nil {
		panic(err)
	}

	strDecr := string(decr)
	tuples := strings.Split(strDecr, ";")
	for _, t := range tuples {
		subStr := strings.Split(t, "=")
		if strings.EqualFold(subStr[0], "admin") {
			return true
		}
	}
	return false
}

func CBCBlitFlippingAttack(cm CBCModule, userData []byte) bool {
	cipherT, err := cm.createUserStr(userData)
	if err != nil {
		panic(err)
	}

	block := cipherT[1*aes.BlockSize : 2*aes.BlockSize]
	block[0] = block[0] ^ byte('?') ^ byte(';')
	block[6] = block[6] ^ byte('?') ^ byte('=')
	block[11] = block[11] ^ byte('?') ^ byte(';')

	for i := aes.BlockSize; i < 2*aes.BlockSize; i++ {
		cipherT[i] = block[i-aes.BlockSize]
	}

	return cm.isConsistStr(cipherT)
}
