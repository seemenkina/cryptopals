package set2

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"github.com/seemenkina/cryptopals/set1"
	"strings"
)

type AESProfiler struct {
	key []byte
}

func (p *AESProfiler) Parse(in string) map[string]string {
	fields := strings.Split(in, "&")
	out := make(map[string]string)
	for _, f := range fields {
		row := strings.Split(f, "=")
		out[row[0]] = row[1]
	}
	return out
}

func (p *AESProfiler) ProfileFor(email string) []byte {
	//uid := mrand.Int() % 100
	return []byte("email=" + email + "&uid=10&role=user")
}

func (p *AESProfiler) EncProfile(email []byte) ([]byte, error) {
	plainT := AddPKCS7Pad(p.ProfileFor(string(email)), aes.BlockSize)
	enc, err := set1.AES128ECBEncrypt(p.key, plainT)
	if err != nil {
		return nil, err
	}
	return enc, nil
}

func (p *AESProfiler) DecProfile(ciphert []byte) (map[string]string, error) {
	decr, err := set1.AES128ECBDecrypt(p.key, ciphert)
	if err != nil {
		return nil, err
	}
	raw, err := RemovePKCS7Pad(decr, aes.BlockSize)
	if err != nil {
		return nil, err
	}
	return p.Parse(string(raw)), nil
}

func createBlock(p AESProfiler, email, word string) []byte {
	chosBlock := AddPKCS7Pad([]byte(word), aes.BlockSize)
	enc, err := p.EncProfile(append([]byte(email), chosBlock...))
	if err != nil {
		return nil
	}
	return enc[aes.BlockSize : aes.BlockSize*2]
}

func ECBCutPasteDetect(p AESProfiler) (map[string]string, error) {
	email := "mail@m.com"

	userBlock := createBlock(p, email, "user")
	suf := []byte(email)
	for i := 0; i < 256; i++ {
		suf = append([]byte("A"), suf...)
		enc, _ := p.EncProfile(suf)
		curBlock := enc[len(enc)-aes.BlockSize:]
		if bytes.Equal(curBlock, userBlock) {
			break
		}
	}
	encUserAttack, err := p.EncProfile(suf)
	if err != nil {
		return nil, fmt.Errorf("ret: %s", err)
	}

	blockAdmin := createBlock(p, email, "admin")
	attackProfile := append(encUserAttack[:len(encUserAttack)-aes.BlockSize], blockAdmin...)

	decr, err := p.DecProfile(attackProfile)
	if err != nil {
		return nil, fmt.Errorf("ret: %s", err)
	}
	return decr, nil
}
