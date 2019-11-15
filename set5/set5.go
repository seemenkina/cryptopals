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

func MITMAttackG(alice, bob *DHAlg, createParams params) ([]byte, []byte) {
	p, g := createParams()
	alice.SetParams(p, g)
	alice.GeneratePrivKey()
	alice.GeneratePublKey()

	bob.SetParams(p, g)
	bob.GeneratePrivKey()
	bob.GeneratePublKey()

	alice.DHHandshake(bob.GetPublKey())
	bob.DHHandshake(alice.GetPublKey())

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

	ONE := new(big.Int).SetUint64(1)

	if g.Cmp(ONE) == 0 {
		plA, _ := Attack(ONE.Bytes(), cipherA, ivA)
		plB, _ := Attack(ONE.Bytes(), cipherB, ivB)
		return plA, plB
	} else if g == p {
		plA, _ := Attack(nil, cipherA, ivA)
		plB, _ := Attack(nil, cipherB, ivB)
		return plA, plB
	} else if g.Cmp(p.Sub(p, ONE)) == 0 {
		plA, err := Attack(ONE.Bytes(), cipherA, ivA)
		if err != nil {
			cand := p.Sub(p, ONE)
			plA, err = Attack(cand.Bytes(), cipherA, ivA)
		}
		plB, err := Attack(ONE.Bytes(), cipherB, ivB)
		if err != nil {
			cand := p.Sub(p, ONE)
			plB, err = Attack(cand.Bytes(), cipherB, ivB)
		}
		return plA, plB
	}
	return nil, nil
}

//type Client struct {
//	p *big.Int
//	g *big.Int
//	clientPubKey *big.Int
//	clientPriKey *big.Int
//	serverPubKey *big.Int
//}
//
//func (cl *Client) SetParams(p, g *big.Int) {
//	cl.p = p
//	cl.g = g
//}
//
//func(cl *Client) ClientHello()(*big.Int, *big.Int, *big.Int){
//	p, err := rand.Prime(rand.Reader, 1024)
//	if err != nil{
//		panic(err)
//	}
//}
