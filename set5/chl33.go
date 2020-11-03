package set5

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"math"
	"math/big"

	"github.com/seemenkina/cryptopals/set2"
)

type DHParticipant struct {
	p       *big.Int
	g       *big.Int
	private *big.Int
	public  *big.Int
	result  *big.Int
}

func (dh *DHParticipant) SetParams(p, g *big.Int) {
	dh.p = p
	dh.g = g
}

func (dh *DHParticipant) GetParams() (*big.Int, *big.Int) {
	return dh.p, dh.g
}

func (dh *DHParticipant) GeneratePrivateKey() {
	private, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		println(fmt.Errorf("can not create private key, %s", err))
		panic(err)
	}
	dh.private = private
}

func (dh *DHParticipant) GeneratePublicKey() {
	dh.public = new(big.Int).Exp(dh.g, dh.private, dh.p)
}

func (dh *DHParticipant) DHHandshake(public *big.Int) {
	dh.result = new(big.Int).Exp(public, dh.private, dh.p)
}

func (dh *DHParticipant) GetPublicKey() *big.Int {
	return dh.public
}

func (dh *DHParticipant) DHResult() []byte {
	return sha256.New().Sum(dh.result.Bytes())
}

func (dh *DHParticipant) Encrypt(msg []byte) ([]byte, []byte, error) {
	key := sha1.New().Sum(dh.result.Bytes())[:aes.BlockSize]
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)
	decr, err := set2.CBCModeEncrypt(iv, msg, key, aes.BlockSize)
	return decr, iv, err
}

func (dh *DHParticipant) Decrypt(cipher, iv []byte) ([]byte, error) {
	key := sha1.New().Sum(dh.result.Bytes())[:aes.BlockSize]
	plainText, err := set2.CBCModeDecrypt(iv, cipher, key, aes.BlockSize)
	return plainText, err
}
