package set3

//DO
func (as *AESStruct) FixedNonceCTRAttackSubstitution(ciphers [][]byte, nonce int) {
	minLen := len(ciphers[0])
	for i := 1; i < len(ciphers); i++ {
		if len(ciphers[i]) < minLen {
			minLen = len(ciphers[i])
		}
	}

	uniformCiphers := make([][]byte, len(ciphers))
	for i := 1; i < len(ciphers); i++ {
		uniformCiphers[i] = ciphers[i][:minLen]
	}
}
