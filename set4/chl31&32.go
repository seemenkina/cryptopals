package set4

import "github.com/seemenkina/cryptopals/set1"

type HmacSHA1Module struct {
	key []byte
}

const (
	SHA1_BLOCK_SIZE = 64
)

func (hsm *HmacSHA1Module) HMACSHA1(msg []byte) [20]byte {
	key := hsm.key
	if len(key) > SHA1_BLOCK_SIZE {
		buf := SHA1(key)
		key = buf[:]
	} else if len(key) < SHA1_BLOCK_SIZE {
		for len(key) != SHA1_BLOCK_SIZE {
			key = append(key, byte(0x00))
		}
	}

	oKeyPad := set1.XorSingleByte(key, byte(0x5c))
	iKeyPad := set1.XorSingleByte(key, byte(0x36))

	firstH := SHA1(append(iKeyPad, msg...))
	return SHA1(append(oKeyPad, firstH[:]...))
}
