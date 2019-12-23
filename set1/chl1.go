package set1

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

//challenge 1 - convert hex to base64
func HexToBase64(input string) (string, error) {
	raw, err := hex.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex: %s", err)
	}
	out := base64.StdEncoding.EncodeToString(raw)
	return out, nil
}
