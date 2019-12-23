package set4

import (
	"bytes"
	"crypto/aes"
	"github.com/seemenkina/cryptopals/set1"
	"github.com/seemenkina/cryptopals/set2"
)

type CBCModule struct {
	IV  []byte
	key []byte
}

func (cm *CBCModule) clientMode(raw []byte) []byte {
	cipher, err := set2.CBCModeEncrypt(cm.IV, raw, cm.key, aes.BlockSize)
	if err != nil {
		panic(err)
	}
	return cipher
}

func (cm *CBCModule) Oracle(cipher []byte) bool {
	_, err := set2.CBCModeDecrypt(cm.IV, cipher, cm.key, aes.BlockSize)
	if err != nil {
		return false
	} else {
		return true
	}
}

func (cm *CBCModule) validateText(raw []byte) ([]byte, error) {
	plain, err := set2.CBCModeDecrypt(cm.IV, raw, cm.key, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(plain); i++ {
		if int(plain[i]) >= 256 {
			return plain, nil
		}
	}
	return plain, nil
}

func AttackCBCKeyIV(raw []byte, cm CBCModule) []byte {
	plain := cm.clientMode(raw)

	var attackPlain []byte
	zeroBlock := []byte{0x00}

	c1 := plain[:aes.BlockSize]
	attackPlain = append(attackPlain, c1...)
	attackPlain = append(attackPlain, bytes.Repeat(zeroBlock, aes.BlockSize)...)
	attackPlain = append(attackPlain, c1...)

	for j := 0; j < 256; j++ {
		attackPlain[31] = byte(j)
		newT, err := cm.validateText(attackPlain)
		if err != nil {
			continue
		} else {
			newT = append(newT, byte(0x01)^byte(j))
			key, _ := set1.XorBuffers(newT[:aes.BlockSize], newT[aes.BlockSize*2:])
			return key
		}
	}
	return nil
}
