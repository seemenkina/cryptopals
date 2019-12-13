package set3

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/seemenkina/cryptopals/set1"
	"github.com/seemenkina/cryptopals/set2"
	"strings"
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

func (as *AESStruct) FixedNonceCTRAttackSubstitution(ciphers [][]byte, nonce int) {
	minLen := len(ciphers[0])
	for i := 1; i < len(ciphers); i++ {
		if len(ciphers[i]) < minLen {
			minLen = len(ciphers[i])
		}
	}

	uniformCiphers := make([][]byte, len(ciphers))
	for i := 1; i < len(ciphers); i++ {
		uniformCiphers[i] = ciphers[i][:minLen]
	}
}

func (as *AESStruct) FixedNonceCTRAttackStatistically(ciphers [][]byte, nonce int) [][]byte {
	var minLen = len(ciphers[0])
	var plainText = make([][]byte, len(ciphers))
	//for j := 0; j < len(ciphers); j++ {
	counts := 0
	for i := 0; i < len(ciphers); i++ {
		if len(ciphers[i]) == 0 {
			counts += 1
		} else if len(ciphers[i]) <= minLen && len(ciphers[i]) != 0 {
			minLen = len(ciphers[i])
		}
	}
	if counts == len(ciphers) {
		return plainText
	}

	for i := 0; i < len(ciphers); i++ {
		if len(ciphers[i]) == 0 {
			ciphers = append(ciphers[:i], ciphers[i+1:]...)
		}
	}

	var xorText []byte
	uniformCiphers := make([][]byte, len(ciphers))
	for i := 0; i < len(ciphers); i++ {
		if len(ciphers[i]) != 0 {
			uniformCiphers[i] = ciphers[i][:minLen]
			//ciphers[i] = ciphers[i][minLen:]
			xorText = append(xorText, uniformCiphers[i]...)
		}
	}
	//for i:=0; i < len(ciphers); i++ {
	//	fmt.Printf("%x\n", ciphers[i])
	//}

	raw, err := BreakingRepeatingKeyXor(xorText, minLen)
	if err != nil {
		panic(err)
	}

	for i := 0; i < len(ciphers); i++ {
		if len(ciphers[i]) != 0 {
			if (i+1)*minLen >= len(raw) {
				plainText[i] = append(plainText[i], raw[i*minLen:]...)
			} else {
				plainText[i] = append(plainText[i], raw[i*minLen:(i+1)*minLen]...)
			}
		}
	}
	//}

	return plainText
}

func BreakingRepeatingKeyXor(raw []byte, keySize int) ([]byte, error) {
	blocks := make([][]byte, keySize)
	for i := 0; i < len(raw); i++ {
		blocks[i%keySize] = append(blocks[i%keySize], raw[i])
	}

	var totKey []byte
	for i := 0; i < keySize; i++ {
		_, key, _ := BruteSingleXor(blocks[i])
		totKey = append(totKey, key)
	}

	totRaw, err := set1.RepeatingKeyXor(totKey, raw)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt by repeating-key xor cipher: %s", err)
	}

	return totRaw, nil
}

func BruteSingleXor(raw []byte) ([]byte, byte, int) {
	rightRaw := make([]byte, len(raw))
	var rightKey byte
	totalWeight := 0

	for i := 1; i < 256; i++ {
		xorRaw := set1.XorSingleByte(raw, byte(i))
		curWeight := 0
		for j := 0; j < len(xorRaw); j++ {
			if int(xorRaw[j]) >= 92 && int(xorRaw[j]) <= 122 || int(xorRaw[j]) == 32 || int(xorRaw[j]) >= 65 && int(xorRaw[j]) <= 90 {
				curWeight += int(xorRaw[j])
			}
		}
		if curWeight > totalWeight {
			totalWeight = curWeight
			rightKey = byte(i)
			rightRaw = xorRaw
		}
	}
	return rightRaw, rightKey, totalWeight
}

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

	encr, err := CTRAES(cm.key, []byte(pad+userStr+suf), cm.nonce)
	if err != nil {
		return nil, err
	}
	return encr, nil
}

func (cm *CTRModule) isConsistStr(cipherT []byte) bool {
	decr, err := CTRAES(cm.key, cipherT, cm.nonce)
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

func CTRBlitflippingAtack(cm CTRModule, userData []byte) bool {
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
