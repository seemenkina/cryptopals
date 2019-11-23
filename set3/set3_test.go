package set3

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAESStruct_PaddingOracleAttack(t *testing.T) {
	msg := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}
	aKey := make([]byte, aes.BlockSize)
	_, _ = rand.Read(aKey)

	as := AESStruct{key: aKey}

	//c := rand2.Intn(9)
	for c := 0; c < 1; c++ {
		raw, _ := base64.StdEncoding.DecodeString(msg[c])
		cip, iv := as.Encrypt(raw)
		as.PadLen(cip, iv)
	}

	//ms := as.PaddingOracleAttack(cip, iv)
	//spew.Dump(ms)
}

func TestCTRAes(t *testing.T) {
	msg := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	raw, _ := base64.StdEncoding.DecodeString(msg)
	input := []struct {
		input    []byte
		expected []byte
		key      []byte
		nonce    int
	}{
		{raw, []byte("Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "),
			[]byte("YELLOW SUBMARINE"), 0},
	}

	for _, tt := range input {
		tt := tt
		t.Run("", func(t *testing.T) {
			cipher, err := CTRAES(tt.key, tt.input, tt.nonce)
			require.NoError(t, err)
			require.EqualValues(t, cipher, tt.expected)
		})
	}

}
