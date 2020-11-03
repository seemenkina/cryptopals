package set5

import "math/big"

func MITMAttackG(alice, bob *DHParticipant, createParams params) ([]byte, []byte) {
	p, g := createParams()
	alice.SetParams(p, g)
	alice.GeneratePrivateKey()
	alice.GeneratePublicKey()

	bob.SetParams(p, g)
	bob.GeneratePrivateKey()
	bob.GeneratePublicKey()

	alice.DHHandshake(bob.GetPublicKey())
	bob.DHHandshake(alice.GetPublicKey())

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
