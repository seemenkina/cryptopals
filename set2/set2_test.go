package set2

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"github.com/seemenkina/cryptopals/set1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAddPKCS7Pad(t *testing.T) {
	tests := []struct {
		input     []byte
		expected  []byte
		blockSize int
	}{
		{[]byte("YELLOW SUBMARINE"), []byte("YELLOW SUBMARINE\x04\x04\x04\x04"), 20},
		{[]byte("YELLOW SUBMARINE"),
			[]byte("YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"), 16},
		{[]byte("YELLOW SUBMARINE YELLOW"),
			[]byte("YELLOW SUBMARINE YELLOW\x09\x09\x09\x09\x09\x09\x09\x09\x09"), 16},
	}
	for _, tt := range tests {
		tt := tt
		t.Run("", func(t *testing.T) {
			current := AddPKCS7Pad(tt.input, tt.blockSize)
			assert.EqualValues(t, tt.expected, current)
		})
	}

}

func TestCBCModeDecrypt(t *testing.T) {
	IV := bytes.Repeat([]byte("\x00"), 16)
	const key = "YELLOW SUBMARINE"

	raw, _ := set1.ReadBase64File("chl10.txt")
	//if err != nil {
	//	return nil, fmt.Errorf("failed to read: %s", err)
	//}

	raw, _ = CBCModeDecrypt(IV, raw, []byte(key), aes.BlockSize)
	//if err != nil {
	//	return nil, fmt.Errorf("faliled to use AES in CBC mode: %s", err)
	//}

}

func TestRandAESKey(t *testing.T) {
	size := 16
	const testSize = 1000
	for i := 0; i < testSize; i++ {
		_, err := GenerateRandBytes(size)
		if err != nil {
			t.Errorf("function return %s", err)
		}
	}
}

func TestAddBytes2Text(t *testing.T) {
	input := []byte("ADD RANDOM BYTE THIS")
	const testSize = 100
	for i := 0; i < testSize; i++ {
		expected, err := AddBytes2Text(input)
		if err != nil {
			t.Errorf("function return %s", err)
		}
		if !bytes.Contains(expected, input) {
			t.Errorf("Input is not contained in output bytes: %s", input)
		}
	}

}

func TestByteAtTimeECBDetect(t *testing.T) {
	const unknownStr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lyb" +
		"GllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unkRaw, _ := base64.StdEncoding.DecodeString(unknownStr)

	tests := []struct {
		input []byte
	}{
		{unkRaw},
		{bytes.Repeat([]byte("A"), 0)},
		{bytes.Repeat([]byte("A"), 1)},
		{bytes.Repeat([]byte("A"), aes.BlockSize-1)},
		{bytes.Repeat([]byte("A"), aes.BlockSize)},
		{bytes.Repeat([]byte("A"), aes.BlockSize+1)},
		{bytes.Repeat([]byte("A"), 3*aes.BlockSize)},
		{bytes.Repeat([]byte("A"), 3*aes.BlockSize-1)},
	}

	for _, tt := range tests {
		input := tt.input
		t.Run("", func(t *testing.T) {
			randKey := make([]byte, aes.BlockSize)
			_, _ = rand.Read(randKey)

			blackBox := newBlockBoxEncrypter(randKey, input)
			revealedText, err := ByteAtTimeECBDetect(blackBox)

			assert.NoError(t, err)
			assert.EqualValues(t, input, revealedText)
		})
	}
}

func TestRemovePKCS7Pad(t *testing.T) {
	tests := []struct {
		input    []byte
		expected []byte
		fail     bool
	}{
		{[]byte("ICE ICE BABY\x04\x04\x04\x04"), []byte("ICE ICE BABY"), false},
		{[]byte("ICE ICE BABY\x05\x05\x05\x05"), nil, true},
		{[]byte("ICE ICE BABY\x01\x02\x03\x04"), nil, true},
		{[]byte("YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"),
			[]byte("YELLOW SUBMARINE"), false},
		{[]byte("YELLOW SUBMARINE YELLOW\x09\x09\x09\x09\x09\x09\x09\x09\x09"),
			[]byte("YELLOW SUBMARINE YELLOW"), false},
		{[]byte("YELLOW SUBMARINE\x01"), nil, true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("", func(t *testing.T) {
			cur, err := RemovePKCS7Pad(tt.input, aes.BlockSize)
			if tt.fail {
				require.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, cur)
			}
		})
	}
}

//func TestByteAtTimeECBDetectHarder(t *testing.T) {
//	const unknownStr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lyb" +
//		"GllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
//	unkRaw, _ := base64.StdEncoding.DecodeString(unknownStr)
//
//	tests := []struct {
//		input []byte
//	}{
//		{unkRaw},
//		{bytes.Repeat([]byte("A"), 0)},
//		{bytes.Repeat([]byte("A"), 1)},
//		{bytes.Repeat([]byte("A"), aes.BlockSize-1)},
//		{bytes.Repeat([]byte("A"), aes.BlockSize)},
//		{bytes.Repeat([]byte("A"), aes.BlockSize+1)},
//		{bytes.Repeat([]byte("A"), 3*aes.BlockSize)},
//		{bytes.Repeat([]byte("A"), 3*aes.BlockSize-1)},
//	}
//
//	for _, tt := range tests {
//		input := tt.input
//		t.Run("", func (t *testing.T) {
//			randKey := make([]byte, aes.BlockSize)
//			_, _ = rand.Read(randKey)
//
//			randPrefix := make([]byte, 2*aes.BlockSize)
//			_, _ = rand.Read(randPrefix)
//
//			blackBox := newHarderBlockBoxEncrypter(randKey, randPrefix, input)
//			revealedText, err := ByteAtTimeECBDetect(blackBox)
//
//			require.NoError(t, err)
//			assert.EqualValues(t, input, revealedText)
//		})
//	}
//}
