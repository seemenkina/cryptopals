package set4

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"github.com/seemenkina/cryptopals/set1"
	"github.com/seemenkina/cryptopals/set2"
	"github.com/seemenkina/cryptopals/set3"
	"math/bits"
	"strings"
)

type CTRModule struct {
	nonce int
	key   []byte
}

func (cm *CTRModule) createUserStr(userData []byte) ([]byte, error) {
	userStr := string(userData)

	pad := "comment1=cooking%20MCs;userdata="
	suf := ";comment2=%20like%20a%20pound%20of%20bacon"

	userStr = strings.ReplaceAll(userStr, ";", "?")
	userStr = strings.ReplaceAll(userStr, "=", "?")

	encr, err := set3.CTRAES(cm.key, []byte(pad+userStr+suf), cm.nonce)
	if err != nil {
		return nil, err
	}
	return encr, nil
}

func (cm *CTRModule) isConsistStr(cipherT []byte) bool {
	decr, err := set3.CTRAES(cm.key, cipherT, cm.nonce)
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

func CTRBlitFlippingAttack(cm CTRModule, userData []byte) bool {
	cipherT, err := cm.createUserStr(userData)
	if err != nil {
		panic(err)
	}
	block := cipherT[2*aes.BlockSize : 3*aes.BlockSize]
	block[0] = block[0] ^ byte('?') ^ byte(';')
	block[6] = block[6] ^ byte('?') ^ byte('=')
	block[11] = block[11] ^ byte('?') ^ byte(';')

	for i := aes.BlockSize; i < 2*aes.BlockSize; i++ {
		cipherT[i] = block[i-aes.BlockSize]
	}

	return cm.isConsistStr(cipherT)
}

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

func msgPadding(msg []byte) []byte {
	lenM := len(msg) * 8
	lenPad := 0
	msg = append(msg, byte(0x80))

	if len(msg) < 56 {
		lenPad = 56 - len(msg)
	} else {
		lenPad = 64 - len(msg)%56
	}
	var padding = make([]byte, lenPad)
	msg = append(msg, padding...)
	var pad = make([]byte, 8)
	binary.BigEndian.PutUint64(pad[:], uint64(lenM))
	msg = append(msg, pad...)
	return msg
}

func SHA1(msg []byte) [20]byte {
	var h0 = uint32(0x67452301)
	var h1 = uint32(0xEFCDAB89)
	var h2 = uint32(0x98BADCFE)
	var h3 = uint32(0x10325476)
	var h4 = uint32(0xC3D2E1F0)
	msg = msgPadding(msg)

	count := len(msg) / 64
	if len(msg)%64 != 0 {
		count += 1
	}
	var part = make([][]byte, count)
	for i := 0; i < count; i++ {
		if (i+1)*64 > len(msg) {
			part[i] = msg[i*64:]
		} else {
			part[i] = msg[i*64 : (i+1)*64]
		}
	}

	for i := 0; i < count; i++ {
		var W = make([]uint32, 320)
		for j := 0; j < 320; j++ {
			if j < 16 {
				W[j] = uint32(part[i][j*4])<<24 | uint32(part[i][j*4+1])<<16 | uint32(part[i][j*4+2])<<8 | uint32(part[i][j*4+3])
			} else {
				W[j] = bits.RotateLeft32(W[j-3]^W[j-8]^W[j-14]^W[j-16], 1)
			}
		}
		a := h0
		b := h1
		c := h2
		d := h3
		e := h4

		var f, k uint32

		//main loop
		for i := 0; i < 80; i++ {
			if i >= 0 && i <= 19 {
				f = (b & c) | ((^b) & d)
				k = 0x5A827999
			} else if i >= 20 && i <= 39 {
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			} else if i >= 40 && i <= 59 {
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			} else if i >= 60 && i <= 79 {
				f = b ^ c ^ d
				k = 0xCA62C1D6
			}

			tmp := bits.RotateLeft32(a, 5) + f + e + k + W[i]
			e = d
			d = c
			c = bits.RotateLeft32(b, 30)
			b = a
			a = tmp
		}
		h0 = h0 + a
		h1 = h1 + b
		h2 = h2 + c
		h3 = h3 + d
		h4 = h4 + e
	}

	var hash [20]byte
	binary.BigEndian.PutUint32(hash[0:], h0)
	binary.BigEndian.PutUint32(hash[4:], h1)
	binary.BigEndian.PutUint32(hash[8:], h2)
	binary.BigEndian.PutUint32(hash[12:], h3)
	binary.BigEndian.PutUint32(hash[16:], h4)
	return hash
}

type SHA1Mac struct {
	key []byte
}
