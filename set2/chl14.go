package set2

import (
	"bytes"
	"crypto/aes"
	"fmt"
)

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
