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
	rand2 "math/rand"
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
	cm := CTRModule{nonce, randKey}

	cipher, err := set3.CTRAES(cm.key, raw, cm.nonce)
	require.NoError(t, err)

	actual := cm.AttackCTRAccess(cipher)
	require.EqualValues(t, raw, actual)
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

func TestSHA1Module(t *testing.T) {
	randKey := make([]byte, aes.BlockSize)
	_, _ = rand.Read(randKey)

	sm := SHA1Module{randKey}

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
			expected := sm.AuthSHA1([]byte(tt.in))
			right := sha1.Sum(append(sm.key, []byte(tt.in)...))
			require.EqualValues(t, expected, right)
			require.EqualValues(t, true, sm.ValidateSHA1([]byte(tt.in), expected))
		})
	}
}

func TestAttackSHA1(t *testing.T) {
	for i := 0; i < 1000; i++ {
		keySize := rand2.Intn(31) + 1
		randKey := make([]byte, keySize)
		_, _ = rand.Read(randKey)

		sm := SHA1Module{randKey}

		msg := "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
		newMsg := ";admin=true"

		ok, _, _, _ := AttackSHA1([]byte(msg), []byte(newMsg), sm.AuthSHA1([]byte(msg)), sm)
		require.EqualValues(t, ok, true)
	}
}
