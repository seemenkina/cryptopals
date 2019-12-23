package set1

//challenge 5 - Implement repeating-key XOR
func RepeatingKeyXor(key []byte, input []byte) ([]byte, error) {
	xorRaw := make([]byte, len(input))

	for i := 0; i < len(input); i++ {
		xorRaw[i] = input[i] ^ key[i%len(key)]
	}
	return xorRaw, nil
}
