package set4

import (
	"bytes"
	"encoding/binary"
	"math/bits"
	"reflect"
)

type SHA1Module struct {
	key []byte
}

func (sm *SHA1Module) AuthSHA1(msg []byte) [20]byte {
	mac := append(sm.key, msg...)
	return SHA1(mac)
}

func (sm *SHA1Module) ValidateSHA1(msg []byte, digest [20]byte) bool {
	mac := append(sm.key, msg...)
	actualDigest := SHA1(mac)
	return reflect.DeepEqual(actualDigest, digest)
}

func MsgUsersPadding(msg, newMsg []byte, msgDigest [20]byte, lenKey int) ([]byte, [20]byte) {
	h := GetH(msgDigest)

	possibleKey := bytes.Repeat([]byte("A"), lenKey)

	possibleMsg := MsgPadding(append(possibleKey, msg...))
	possibleMsg = append(possibleMsg, newMsg...)

	padMsg := OtherMsgPadding(newMsg, len(possibleMsg)*8)
	expectedDigest := OtherSHA1(padMsg, h)

	return possibleMsg[lenKey:], expectedDigest
}

func AttackSHA1(msg, newMsg []byte, msgDigest [20]byte, module SHA1Module) (bool, int, []byte, [20]byte) {
	for i := 1; i < 64; i++ {
		m, d := MsgUsersPadding(msg, newMsg, msgDigest, i)
		if module.ValidateSHA1(m, d) {
			return true, i, m, d
		}
	}
	return false, 0, nil, [20]byte{}
}

// lenM - length in bits
func OtherMsgPadding(msg []byte, lenM int) []byte {
	lenPad := 0
	msg = append(msg, byte(0x80))

	if len(msg) < 56 {
		lenPad = 56 - len(msg)
	} else {
		lenPad = 64 - len(msg)%56
	}
	var padding = make([]byte, lenPad)
	msg = append(msg, padding...)
	var pad = make([]byte, 8)
	binary.BigEndian.PutUint64(pad[:], uint64(lenM))
	msg = append(msg, pad...)
	return msg
}

func GetH(digest [20]byte) []uint32 {
	h := make([]uint32, 5)

	h[0] = binary.BigEndian.Uint32(digest[0:])
	h[1] = binary.BigEndian.Uint32(digest[4:])
	h[2] = binary.BigEndian.Uint32(digest[8:])
	h[3] = binary.BigEndian.Uint32(digest[12:])
	h[4] = binary.BigEndian.Uint32(digest[16:])

	return h
}

func OtherSHA1(msg []byte, h []uint32) [20]byte {
	var h0 = h[0]
	var h1 = h[1]
	var h2 = h[2]
	var h3 = h[3]
	var h4 = h[4]

	count := len(msg) / 64
	if len(msg)%64 != 0 {
		count += 1
	}
	var part = make([][]byte, count)
	for i := 0; i < count; i++ {
		if (i+1)*64 > len(msg) {
			part[i] = msg[i*64:]
		} else {
			part[i] = msg[i*64 : (i+1)*64]
		}
	}

	for i := 0; i < count; i++ {
		var W = make([]uint32, 320)
		for j := 0; j < 320; j++ {
			if j < 16 {
				W[j] = uint32(part[i][j*4])<<24 | uint32(part[i][j*4+1])<<16 | uint32(part[i][j*4+2])<<8 | uint32(part[i][j*4+3])
			} else {
				W[j] = bits.RotateLeft32(W[j-3]^W[j-8]^W[j-14]^W[j-16], 1)
			}
		}
		a := h0
		b := h1
		c := h2
		d := h3
		e := h4

		var f, k uint32

		//main loop
		for i := 0; i < 80; i++ {
			if i >= 0 && i <= 19 {
				f = (b & c) | ((^b) & d)
				k = 0x5A827999
			} else if i >= 20 && i <= 39 {
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			} else if i >= 40 && i <= 59 {
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			} else if i >= 60 && i <= 79 {
				f = b ^ c ^ d
				k = 0xCA62C1D6
			}

			tmp := bits.RotateLeft32(a, 5) + f + e + k + W[i]
			e = d
			d = c
			c = bits.RotateLeft32(b, 30)
			b = a
			a = tmp
		}
		h0 = h0 + a
		h1 = h1 + b
		h2 = h2 + c
		h3 = h3 + d
		h4 = h4 + e
	}

	var hash [20]byte
	binary.BigEndian.PutUint32(hash[0:], h0)
	binary.BigEndian.PutUint32(hash[4:], h1)
	binary.BigEndian.PutUint32(hash[8:], h2)
	binary.BigEndian.PutUint32(hash[12:], h3)
	binary.BigEndian.PutUint32(hash[16:], h4)
	return hash
}
