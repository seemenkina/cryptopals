package set4

import (
	"bytes"
	"github.com/seemenkina/cryptopals/set1"
	"github.com/seemenkina/cryptopals/set3"
)

func (cm *CTRModule) AttackCTRAccess(cipher []byte) []byte {
	zeroBlock := []byte{0x00}
	recText := cm.edit(cipher, bytes.Repeat(zeroBlock, len(cipher)), 0)
	xorT, _ := set1.XorBuffers(recText, cipher)
	return xorT
}

func (cm *CTRModule) edit(cipher, newText []byte, offset int) []byte {
	zeroBlock := []byte{0x00}
	zero := bytes.Repeat(zeroBlock, len(cipher))
	newT := bytes.Replace(zero, zero[offset:offset+len(newText)], newText, len(newText))
	cp, err := set3.CTRAES(cm.key, newT, cm.nonce)
	if err != nil {
		return nil
	}
	newCT := bytes.Replace(cipher, cipher[offset:offset+len(newText)], cp[offset:offset+len(newText)], len(newT))
	return newCT
}
