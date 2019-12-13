package set2

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"github.com/davecgh/go-spew/spew"
	"github.com/seemenkina/cryptopals/set1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	mrand "math/rand"
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

func TestCBCModeDecryptChl(t *testing.T) {
	IV := bytes.Repeat([]byte("\x00"), 16)
	const key = "YELLOW SUBMARINE"
	raw, _ := set1.ReadBase64File("chl10.txt")

	input := []struct {
		cipherT []byte
		IV      []byte
		key     []byte
	}{
		{raw, IV, []byte(key)},
	}

	for _, tt := range input {
		tt := tt
		t.Run("", func(t *testing.T) {
			_, err := CBCModeDecrypt(tt.IV, tt.cipherT, tt.key, aes.BlockSize)
			require.NoError(t, err)
		})
	}
}

func TestCBCModeNist(t *testing.T) {
	plain, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c4" +
		"6a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	cipher, _ := hex.DecodeString("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b" +
		"273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7")
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	IV, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")

	input := []struct {
		plainT  []byte
		cipherT []byte
		IV      []byte
		key     []byte
	}{
		{plain, cipher, IV, key},
	}

	for _, tt := range input {
		tt := tt
		t.Run("", func(t *testing.T) {
			encr, err := CBCModeEncrypt(tt.IV, tt.plainT, tt.key, aes.BlockSize)
			decr, err := CBCModeDecrypt(tt.IV, encr, tt.key, aes.BlockSize)
			require.NoError(t, err)

			assert.EqualValues(t, decr, tt.plainT)
		})
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

func TestBlackBox(t *testing.T) {
	BlackBox(EncryptionOracle)
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

func TestProfileManager(t *testing.T) {
	input := []struct {
		email       string
		profileDict map[string]string
		profile     string
	}{
		{"foo@bar.com", map[string]string{
			"email": "foo@bar.com",
			"uid":   "10",
			"role":  "user",
		}, "email=foo@bar.com&uid=10&role=user"},
	}
	for _, tt := range input {
		tt := tt
		t.Run("", func(t *testing.T) {
			randKey := make([]byte, aes.BlockSize)
			_, _ = rand.Read(randKey)
			p := AESProfiler{key: randKey}
			actualEncrypt, err := p.EncProfile([]byte(tt.email))
			actualDecrypt, err := p.DecProfile(actualEncrypt)
			actualProfile := p.ProfileFor(tt.email)
			require.NoError(t, err)
			assert.EqualValues(t, tt.profileDict, actualDecrypt)
			assert.EqualValues(t, tt.profile, string(actualProfile))
		})
	}
}

func TestECBCutPasteDetect(t *testing.T) {
	const testSize = 1000
	for i := 0; i < testSize; i++ {
		randKey := make([]byte, aes.BlockSize)
		_, _ = rand.Read(randKey)
		p := AESProfiler{key: randKey}
		dict, err := ECBCutPasteDetect(p)
		expected := "admin"
		require.NoError(t, err)
		assert.EqualValues(t, dict["role"], expected)
	}
}

func TestByteAtTimeECBDetectHarder(t *testing.T) {
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
			const testSize = 100
			for i := 0; i < testSize; i++ {
				n := mrand.Int() % 50
				randPrefix := make([]byte, n)
				_, _ = rand.Read(randPrefix)
				blackBox := newHarderBlockBoxEncrypter(randKey, randPrefix, input)
				revealedText, err := ByteAtTimeECBDetectHarder(blackBox)
				if err != nil {
					spew.Dump(randKey, randPrefix)
				}
				require.NoError(t, err)
				assert.EqualValues(t, input, revealedText)
			}
		})
	}
}

func TestCBCBlitflippingAtack(t *testing.T) {
	randKey := make([]byte, aes.BlockSize)
	_, _ = rand.Read(randKey)
	randIV := make([]byte, aes.BlockSize)
	_, _ = rand.Read(randIV)

	userDataTrue := ";admin=true;"
	cm := CBCModule{randIV, randKey}

	flag := CBCBlitFlippingAttack(cm, []byte(userDataTrue))
	assert.EqualValues(t, flag, true)
}
