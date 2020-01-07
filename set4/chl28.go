package set4

import (
	"encoding/binary"
	"math/bits"
)

func MsgPadding(msg []byte) []byte {
	lenM := len(msg) * 8
	msg = append(msg, byte(0x80))

	for (len(msg)*8)%512 != 448 {
		msg = append(msg, byte(0x00))
	}
	var pad = make([]byte, 8)
	binary.BigEndian.PutUint64(pad[:], uint64(lenM))
	msg = append(msg, pad...)
	return msg
}

func SHA1(msg []byte) [20]byte {
	var h0 = uint32(0x67452301)
	var h1 = uint32(0xEFCDAB89)
	var h2 = uint32(0x98BADCFE)
	var h3 = uint32(0x10325476)
	var h4 = uint32(0xC3D2E1F0)
	msg = MsgPadding(msg)

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
