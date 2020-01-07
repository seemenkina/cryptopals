package set4

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/seemenkina/cryptopals/set3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	rand2 "math/rand"
	"net/http"
	"net/url"
	"testing"
	"time"
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
		keySize := rand2.Intn(63) + 1
		randKey := make([]byte, keySize)
		_, _ = rand.Read(randKey)

		sm := SHA1Module{randKey}

		msg := "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
		newMsg := ";admin=true"

		ok, _, _, _ := AttackSHA1([]byte(msg), []byte(newMsg), sm.AuthSHA1([]byte(msg)), sm)
		require.EqualValues(t, ok, true)
	}
}

func TestHmacSHA1Module_HMACSHA1(t *testing.T) {
	keySize := rand2.Intn(63) + 1
	randKey := make([]byte, keySize)
	_, _ = rand.Read(randKey)

	hsm := HmacSHA1Module{[]byte("key")}
	actual := hsm.HMACSHA1([]byte("The quick brown fox jumps over the lazy dog"))

	mac := hmac.New(sha1.New, hsm.key)
	mac.Write([]byte("The quick brown fox jumps over the lazy dog"))
	expected := mac.Sum(nil)
	require.EqualValues(t, expected, actual[:])
}

//test works 1 hour
func TestServer(t *testing.T) {
	keySize := rand2.Intn(63) + 1
	randKey := make([]byte, keySize)
	_, _ = rand.Read(randKey)

	hsm := HmacSHA1Module{randKey}
	msg := []byte("The quick brown fox jumps over the lazy dog")

	go func() {
		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			msgBytes := r.URL.Query().Get("file")
			msg, err := url.QueryUnescape(msgBytes)
			if err != nil {
				t.Fatalf("Failed to decode msg: %s", err)
			}

			digestHex := r.URL.Query().Get("signature")
			digest, err := hex.DecodeString(digestHex)
			if err != nil {
				t.Fatalf("Failed to decode digest: %s", err)
			}

			expected := hsm.HMACSHA1([]byte(msg))
			if len(expected) != len(digest) {
				w.WriteHeader(500)
				return
			}
			for i := 0; i < len(digest); i++ {
				time.Sleep(5 * time.Millisecond)
				if digest[i] != expected[i] {
					w.WriteHeader(500)
					return
				}
			}
		})
		if err := http.ListenAndServe(":9000", nil); err != nil {
			t.Fatalf("Failed to serve: %s", err)
		}
	}()

	send := func(msg, digest []byte) (bool, time.Duration) {
		msgB := url.QueryEscape(string(msg))
		digestB := hex.EncodeToString(digest)

		req, err := http.NewRequest("GET", "http://localhost:9000/", nil)
		if err != nil {
			t.Fatalf("Failed to create new http requests: %s", err)
		}

		params := req.URL.Query()
		params.Add("file", msgB)
		params.Add("signature", digestB)
		req.URL.RawQuery = params.Encode()

		timeS := time.Now()
		resp, err := http.DefaultClient.Do(req)
		timeE := time.Now().Sub(timeS)
		if err != nil {
			t.Fatalf("Failed in http client: %s", err)
		}
		if resp.StatusCode == 200 {
			return true, timeE
		}
		return false, timeE
	}

	corMac := make([]byte, 1)
	ok, timeE := send(msg, corMac)

	for timeE.Milliseconds()/5 < 1 {
		corMac = append(corMac, byte(0x00))
		ok, timeE = send(msg, corMac)
	}
	lenMac := len(corMac)

	for i := 0; i < lenMac; i++ {
		maxTimes := 0
		var maxByte byte
		for j := 0; j < 256; j++ {
			corMac[i] = byte(j)
			sum := 0
			for k := 0; k < 10; k++ {
				ok, timeE = send(msg, corMac)
				sum += int(timeE.Milliseconds())
			}
			if sum > maxTimes {
				maxTimes = sum
				maxByte = byte(j)
			}
		}
		corMac[i] = maxByte
	}
	require.EqualValues(t, ok, true)
}
