package set1

//challenge2 - Write a function that takes two equal-length buffers and produces their XOR combination.
func XorBuffers(raw1, raw2 []byte) ([]byte, error) {
	xorBuf := make([]byte, len(raw1))
	for i := 0; i < len(raw1); i++ {
		xorBuf[i] = raw1[i] ^ raw2[i]
	}
	return xorBuf, nil
}
