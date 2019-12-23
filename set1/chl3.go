package set1

//challenge 3 - single byte xor ciphers
func BruteSingleXor(raw []byte) ([]byte, byte, float64) {
	rightRaw := make([]byte, len(raw))
	var rightKey byte
	totalWeight := 0.0

	for i := 1; i < 256; i++ {
		xorRaw := XorSingleByte(raw, byte(i))
		curWeight := 0.0
		curWeight = textWeight(xorRaw)
		if curWeight > totalWeight {
			totalWeight = curWeight
			rightKey = byte(i)
			rightRaw = xorRaw
		}
	}
	return rightRaw, rightKey, totalWeight
}

func XorSingleByte(raw []byte, singleByte byte) []byte {
	xorRaw := make([]byte, len(raw))
	for i := 0; i < len(raw); i++ {
		xorRaw[i] = raw[i] ^ singleByte
	}
	return xorRaw
}
