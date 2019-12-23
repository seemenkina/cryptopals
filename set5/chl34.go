package set5

import (
	"crypto/aes"
	"crypto/sha1"
	"github.com/seemenkina/cryptopals/set2"
	"math/big"
)

type params func() (*big.Int, *big.Int)

func Attack(candidate, cipher, iv []byte) ([]byte, error) {
	key := sha1.New().Sum(candidate)[:aes.BlockSize]
	plainMiddle, err := set2.CBCModeDecrypt(iv, cipher, key, aes.BlockSize)
	return plainMiddle, err
}

func MITMAttack(alice, bob *DHAlg, createParams params) ([]byte, []byte) {
	p, g := createParams()
	alice.SetParams(p, g)
	alice.GeneratePrivKey()
	alice.GeneratePublKey()

	bob.SetParams(p, g)
	bob.GeneratePrivKey()
	bob.GeneratePublKey()

	alice.DHHandshake(p)
	bob.DHHandshake(p)

	cipherA, ivA, err := alice.Encrypt([]byte("msg"))
	if err != nil {
		panic(err)
	}

	plainTA, err := bob.Decrypt(cipherA, ivA)
	if err != nil {
		panic(err)
	}

	cipherB, ivB, err := bob.Encrypt(plainTA)
	if err != nil {
		panic(err)
	}

	//p**a %p == 0, p**b %p == 0 instead of B**a %p, A**b %p
	pma, _ := Attack(nil, cipherA, ivA)
	pmb, _ := Attack(nil, cipherB, ivB)
	return pma, pmb
}
