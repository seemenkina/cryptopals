package set2

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/seemenkina/cryptopals/set1"
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
	for i := len(block) - padSize; i < len(block); i++ {
		if block[i] != padCharacter {
			return false, 0
		}
	}
	return true, padSize
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
	spew.Dump(decrypted)
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

	plainText = AddPKCS7Pad(plainText, keySize)

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

type boxFunc func([]byte) []byte

func newBlockBoxEncrypter(key, secret []byte) func(plainText []byte) []byte {
	return func(plainText []byte) []byte {
		plainText = append(plainText, secret...)
		plainText = AddPKCS7Pad(plainText, aes.BlockSize)

		encr, err := set1.AES128ECB(key, plainText)
		if err != nil {
			panic("encr failed" + err.Error())
		}
		return encr
	}
}
func newHarderBlockBoxEncrypter(key, prefix, secret []byte) func(plainText []byte) []byte {
	bb := newBlockBoxEncrypter(key, secret)
	return func(plainText []byte) []byte {
		return bb(append(prefix, plainText...))
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
