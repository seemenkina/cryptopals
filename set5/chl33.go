package set5

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"github.com/seemenkina/cryptopals/set2"
	"math"
	"math/big"
)

type DHAlg struct {
	p     *big.Int
	g     *big.Int
	privK *big.Int
	publK *big.Int
	sKey  *big.Int
}

func (dh *DHAlg) SetParams(p, g *big.Int) {
	dh.p = p
	dh.g = g
}

func (dh *DHAlg) GetParams() (*big.Int, *big.Int) {
	return dh.p, dh.g
}

func (dh *DHAlg) GeneratePrivKey() {
	res, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		println(fmt.Errorf("can not create private key, %s", err))
		panic(err)
	}
	dh.privK = res
}

func (dh *DHAlg) GeneratePublKey() {
	dh.publK = new(big.Int).Exp(dh.g, dh.privK, dh.p)
}

func (dh *DHAlg) DHHandshake(pubK *big.Int) {
	dh.sKey = new(big.Int).Exp(pubK, dh.privK, dh.p)
}

func (dh *DHAlg) GetPublKey() *big.Int {
	return dh.publK
}

func (dh *DHAlg) GetSKey() []byte {
	return sha256.New().Sum(dh.sKey.Bytes())
}

func (dh *DHAlg) Encrypt(msg []byte) ([]byte, []byte, error) {
	key := sha1.New().Sum(dh.sKey.Bytes())[:aes.BlockSize]
	iv := make([]byte, aes.BlockSize)
	_, _ = rand.Read(iv)
	decr, err := set2.CBCModeEncrypt(iv, msg, key, aes.BlockSize)
	return decr, iv, err
}

func (dh *DHAlg) Decrypt(cipher, iv []byte) ([]byte, error) {
	key := sha1.New().Sum(dh.sKey.Bytes())[:aes.BlockSize]
	plainText, err := set2.CBCModeDecrypt(iv, cipher, key, aes.BlockSize)
	return plainText, err
}
