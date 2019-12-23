package set4

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/seemenkina/cryptopals/set3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"testing"
)

func ReadBase64File(fileName string) ([]byte, error) {
	buffer, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read file; %s", err)
	}

	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(buffer)))
	n, err := base64.StdEncoding.Decode(decoded, buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to decode file; %s", err)
	}

	return decoded[:n], nil
}

func TestCTRBlitFlippingAtack(t *testing.T) {
	randKey := make([]byte, aes.BlockSize)
	_, _ = rand.Read(randKey)
	nonce := 0

	userDataTrue := ";admin=true;"
	cm := CTRModule{nonce, randKey}

	flag := CTRBlitFlippingAttack(cm, []byte(userDataTrue))
	assert.EqualValues(t, flag, true)
}

func TestAttackCBCKeyIV(t *testing.T) {
	randIV := make([]byte, aes.BlockSize)
	_, _ = rand.Read(randIV)

	userDataTrue := "comment1=cooking%20MCs;userdata=;admin=truetrue;"
	cm := CBCModule{randIV, randIV}

	key := AttackCBCKeyIV([]byte(userDataTrue), cm)
	assert.EqualValues(t, key, randIV)
}

func TestAttackCTRAccess(t *testing.T) {
	raw, err := ReadBase64File("../set1/chl7.txt")
	require.NoError(t, err)
	randKey := make([]byte, aes.BlockSize)
	_, _ = rand.Read(randKey)
	nonce := 0
	//cm := CTRModule{nonce, randKey}

	cipher, err := set3.CTRAES(randKey, raw, nonce)
	require.NoError(t, err)

	AttackCTRAccess(cipher)
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
