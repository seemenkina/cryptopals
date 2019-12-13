package set4

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCTRBlitFlippingAtack(t *testing.T) {
	randKey := make([]byte, aes.BlockSize)
	_, _ = rand.Read(randKey)
	nonce := 0

	userDataTrue := ";admin=true;"
	cm := CTRModule{nonce, randKey}

	flag := CTRBlitFlippingAttack(cm, []byte(userDataTrue))
	assert.EqualValues(t, flag, true)
}

func TestCBCKeyIV(t *testing.T) {
	randIV := make([]byte, aes.BlockSize)
	_, _ = rand.Read(randIV)

	userDataTrue := "comment1=cooking%20MCs;userdata=;admin=truetrue;"
	cm := CBCModule{randIV, randIV}

	key := AttackCBCKeyIV([]byte(userDataTrue), cm)
	assert.EqualValues(t, key, randIV)
}

func TestSHA1(t *testing.T) {

	test := []struct {
		in string
	}{
		{"abc"},
		{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"},
		{string(bytes.Repeat([]byte("a"), 1000000))},
		{""},
	}

	for _, tt := range test {
		tt := tt
		t.Run("", func(t *testing.T) {
			expected := SHA1([]byte(tt.in))
			right := sha1.Sum([]byte(tt.in))
			require.EqualValues(t, expected, right)
		})
	}
}

func TestSHA12(t *testing.T) {

}
