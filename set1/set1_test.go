package set1

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHexToBase64(t *testing.T) {
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	actual, err := HexToBase64(input)
	if err != nil {
		t.Error(err)
	}
	if expected != actual {
		t.Error("Expected ", expected, " \n got ", actual)
	}
}

func TestXorBuffers(t *testing.T) {
	firstInput := "1c0111001f010100061a024b53535009181c"
	secondInput := "686974207468652062756c6c277320657965"
	raw1, err := hex.DecodeString(firstInput)
	if err != nil {
		t.Error(err)
	}
	raw2, err := hex.DecodeString(secondInput)
	if err != nil {
		t.Error(err)
	}
	expected := "746865206b696420646f6e277420706c6179"

	actual, err := XorBuffers(raw1, raw2)
	if err != nil {
		t.Error(err)
	}
	if expected != hex.EncodeToString(actual) {
		t.Error("Expected ", expected, " \n got ", actual)
	}
}

func TestXorSingleByte(t *testing.T) {
	input, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	expected := "Cooking MC's like a pound of bacon"
	actual, err := Chl3BruteSingleXor(input)
	if err != nil {
		t.Error(err)
	}
	if expected != string(actual) {
		t.Error("Expected ", expected, " \n got ", string(actual))
	}
}

func TestFindSingleXorKey(t *testing.T) {
	expected := "Now that the party is jumping\n"
	actual, err := FindSingleXorKey("chl4.txt")
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal([]byte(expected), actual) {
		t.Error("Expected ", []byte(expected), " \n got ", actual)
	}
}

func TestRepeatingKeyXor(t *testing.T) {
	input := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := "ICE"
	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
	actual, err := RepeatingKeyXor([]byte(key), []byte(input))
	actualstr := hex.EncodeToString(actual)
	if err != nil {
		t.Error(err)
	}
	if expected != actualstr {
		t.Error("Expected ", expected, " \n got ", actualstr)
	}
}

func TestAES128ECB(t *testing.T) {
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	plainText, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191" +
		"a0a52eff69f2445df4f9b17ad2b417be66c3710")
	expected, _ := hex.DecodeString("3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3e" +
		"d0306887b0c785e27e8ad3f8223207104725dd4")
	actual, err := AES128ECB(key, plainText)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(expected, actual) {
		t.Error("Expected ", expected, " \n got ", actual)
	}
}
