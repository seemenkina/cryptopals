package set2

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"github.com/seemenkina/cryptopals/set1"
	"strings"
)

//challenge 9
func AddPKCS7Pad(raw []byte, lenBlock int) []byte {
	padLen := lenBlock - (len(raw) % lenBlock)
	var padding []byte
	padding = append(padding, byte(padLen))
	padding = bytes.Repeat(padding, padLen)
	raw = append(raw, padding...)
	return raw
}

func RemovePKCS7Pad(raw []byte, blockSize int) ([]byte, error) {
	var rawLen = len(raw)
	if rawLen%blockSize != 0 {
		return nil, fmt.Errorf("data's length isn't a multiple of blockSize")
	}
	padBlock := raw[rawLen-blockSize:]

	if ok, padLen := PaddingValidation(padBlock); ok {
		return raw[:rawLen-padLen], nil
	} else {
		return nil, fmt.Errorf("incorrect padding in last block")
	}
}

func PaddingValidation(block []byte) (bool, int) {
	padCharacter := block[len(block)-1]
	padSize := int(padCharacter)
	if padSize > aes.BlockSize || padSize == 0 {
		return false, 0
	}
	for i := len(block) - padSize; i < len(block); i++ {
		if block[i] != padCharacter {
			return false, 0
		}
	}
	return true, padSize
}

func CBCModeDecrypt(IV []byte, raw []byte, key []byte, size int) ([]byte, error) {
	prevBlock := IV
	var decrypted []byte
	for bs, be := 0, size; bs < len(raw); bs, be = bs+size, be+size {
		curBlock := raw[bs:be]
		encBlock, err := set1.AES128ECBDecrypt(key, curBlock)
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
	raw = AddPKCS7Pad(raw, size)
	prevBlock := IV
	var decrypted []byte
	for bs, be := 0, size; bs < len(raw); bs, be = bs+size, be+size {
		curBlock := raw[bs:be]
		block, _ := set1.XorBuffers(curBlock, prevBlock)
		encBlock, err := set1.AES128ECBEncrypt(key, block)
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

type boxFunc func([]byte) []byte

func newBlockBoxEncrypter(key, secret []byte) func(plainText []byte) []byte {
	return func(plainText []byte) []byte {
		plainText = append(plainText, secret...)
		plainText = AddPKCS7Pad(plainText, aes.BlockSize)

		encr, err := set1.AES128ECBDecrypt(key, plainText)
		if err != nil {
			panic("encr failed" + err.Error())
		}
		return encr
	}
}

func blockOracle(blackBox boxFunc) int {

	suf := []byte("")
	enc := blackBox(suf)
	prevBlockCount := len(enc)

	for i := 0; i < 256; i++ {
		suf = append(suf, 0)
		enc := blackBox(suf)
		curBlockCount := len(enc)
		if prevBlockCount != curBlockCount {
			return curBlockCount - prevBlockCount
		}
	}
	panic("block counter failed")
}

func ByteAtTimeECBDetect(blackBox boxFunc) ([]byte, error) {
	var out []byte
	blockSize := blockOracle(blackBox)

	enc := blackBox([]byte(""))
	numBlocks := len(enc)/blockSize + 1
	appendBlocks := bytes.Repeat([]byte("A"), numBlocks*blockSize)
	goodLen := len(appendBlocks)

	for i := 0; i < goodLen; i++ {
		appendBlocks = appendBlocks[1:]

		enc := blackBox(appendBlocks)
		block := enc[blockSize*(numBlocks-1) : blockSize*numBlocks]

		knowText := append(appendBlocks, out...)
		knownBlock := knowText[len(knowText)-blockSize+1:]
		letter, ok := detectLetter(blackBox, block, knownBlock)
		if !ok {
			break
		}
		out = append(out, letter)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("failed to find anything")
	}
	if lb := out[len(out)-1]; lb != 0x1 {
		return nil, fmt.Errorf("unexpected last byte %x", lb)
	}
	return out[:len(out)-1], nil
}

func detectLetter(blackBox boxFunc, unkBlock, knownBlock []byte) (byte, bool) {
	for i := 0; i < 256; i++ {
		block := append(knownBlock, byte(i))
		encr := blackBox(block)
		if bytes.Equal(encr[:len(block)], unkBlock) {
			return byte(i), true
		}
	}
	return 0, false
}

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

func newHarderBlockBoxEncrypter(key, prefix, secret []byte) func(plainText []byte) []byte {
	bb := newBlockBoxEncrypter(key, secret)
	return func(plainText []byte) []byte {
		return bb(append(prefix, plainText...))
	}
}

func prefix(blackBox boxFunc, blockSize int) (int, int) {
	var zeroBlock []byte
	suf := bytes.Repeat([]byte("0"), blockSize*3)
	encZeroBlocks := blackBox(suf)
	var inde int

	if ok, ind := IndexRepetedBlock(encZeroBlocks); ok {
		inde = ind
		zeroBlock = encZeroBlocks[ind*blockSize : (ind+1)*blockSize]
	}
	suf = []byte("")
	for i := 0; i < 256; i++ {
		suf = append(suf, []byte("0")...)
		enc := blackBox(suf)
		if bytes.Contains(enc, zeroBlock) {
			return (i + 1) % blockSize, inde
		}
	}
	panic("block counter failed")
}

func IndexRepetedBlock(data []byte) (bool, int) {
	blockCount := len(data) / aes.BlockSize
	blocks := make([][]byte, blockCount)
	for i := 0; i < blockCount; i++ {
		blocks[i] = data[i*aes.BlockSize : (i+1)*aes.BlockSize]
	}

	for i := 0; i < blockCount; i++ {
		for j := i + 1; j < blockCount; j++ {
			if bytes.Equal(blocks[i], blocks[j]) {
				return true, i
			}
		}
	}
	return false, -1
}

func ByteAtTimeECBDetectHarder(blackBox boxFunc) ([]byte, error) {
	var out []byte
	blockSize := blockOracle(blackBox)
	enc := blackBox([]byte(""))

	prefsPadSize, lenB := prefix(blackBox, blockSize)

	numBlocks := len(enc)/blockSize + 1
	appendBlocks := bytes.Repeat([]byte("A"), numBlocks*blockSize+prefsPadSize)
	goodLen := len(appendBlocks)

	for i := 0; i < goodLen; i++ {
		appendBlocks = appendBlocks[1:]
		enc := blackBox(appendBlocks)
		block := enc[blockSize*(numBlocks+lenB-1) : blockSize*(numBlocks+lenB)]
		knowText := append(appendBlocks, out...)
		knownBlock := knowText[len(knowText)-blockSize-prefsPadSize+1:]
		letter, ok := detectLetterHarder(blackBox, block, knownBlock, lenB)
		if !ok {
			break
		}
		out = append(out, letter)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("failed to find anything")
	}

	if lb := out[len(out)-1]; lb != 0x1 {
		return nil, fmt.Errorf("unexpected last byte %x", lb)
	}
	return out[:len(out)-1], nil
}

func detectLetterHarder(blackBox boxFunc, unkBlock, knownBlock []byte, prefSize int) (byte, bool) {
	for i := 0; i < 256; i++ {
		block := append(knownBlock, byte(i))
		encr := blackBox(block)
		blockNum := len(block)/aes.BlockSize + prefSize

		if bytes.Equal(encr[(blockNum-1)*aes.BlockSize:(blockNum)*aes.BlockSize], unkBlock) {
			return byte(i), true
		}
	}
	return 0, false
}

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

func CBCBlitflippingAtack(cm CBCModule, userData []byte) bool {
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
