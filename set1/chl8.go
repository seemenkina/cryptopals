package set1

import (
	"bytes"
	"crypto/aes"
)

func HasRepeatedBlock(data []byte) bool {
	blockCount := len(data) / aes.BlockSize
	blocks := make([][]byte, blockCount)
	for i := 0; i < blockCount; i++ {
		blocks[i] = data[i*aes.BlockSize : (i+1)*aes.BlockSize]
	}

	for i := 0; i < blockCount; i++ {
		for j := i + 1; j < blockCount; j++ {
			if bytes.Equal(blocks[i], blocks[j]) {
				return true
			}
		}
	}
	return false
}
