package set2

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"github.com/seemenkina/cryptopals/set1"
)

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
