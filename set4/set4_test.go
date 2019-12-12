package set4

import (
	"bytes"
	"crypto/sha1"
	"github.com/stretchr/testify/require"
	"testing"
)

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
