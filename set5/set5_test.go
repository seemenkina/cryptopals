package set5

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestDiffieHellman(t *testing.T) {
	alice := DHAlg{}
	bob := DHAlg{}

	p := new(big.Int).SetBytes([]byte("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea" +
		"63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a" +
		"637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d" +
		"39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca23732" +
		"7ffffffffffffffff"))
	g := new(big.Int).SetUint64(2)

	alice.SetParams(p, g)
	alice.GeneratePrivKey()
	alice.GeneratePublKey()

	bob.SetParams(p, g)
	bob.GeneratePrivKey()
	bob.GeneratePublKey()

	alice.DHHandshake(bob.GetPublKey())
	bob.DHHandshake(alice.GetPublKey())

	assert.EqualValues(t, alice.GetSKey(), bob.GetSKey())
}

func TestDHEncrypt(t *testing.T) {
	alice := DHAlg{}
	bob := DHAlg{}

	p := new(big.Int).SetBytes([]byte("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea" +
		"63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a" +
		"637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d" +
		"39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca23732" +
		"7ffffffffffffffff"))
	g := new(big.Int).SetUint64(2)
	message := "Secret message"

	alice.SetParams(p, g)
	alice.GeneratePrivKey()
	alice.GeneratePublKey()

	bob.SetParams(p, g)
	bob.GeneratePrivKey()
	bob.GeneratePublKey()

	alice.DHHandshake(bob.GetPublKey())
	bob.DHHandshake(alice.GetPublKey())

	encrAlice, iv, err := alice.Encrypt([]byte(message))
	require.NoError(t, err)

	msg, err := bob.Decrypt(encrAlice, iv)
	require.NoError(t, err)

	assert.EqualValues(t, message, msg)
}

func GetHardcodeParams() (*big.Int, *big.Int) {
	p := new(big.Int).SetBytes([]byte("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea" +
		"63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a" +
		"637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d" +
		"39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca23732" +
		"7ffffffffffffffff"))
	g := new(big.Int).SetUint64(2)
	return p, g
}

func GetParamG1() (*big.Int, *big.Int) {
	p := new(big.Int).SetBytes([]byte("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea" +
		"63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a" +
		"637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d" +
		"39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca23732" +
		"7ffffffffffffffff"))
	g := new(big.Int).SetUint64(1)
	return p, g
}

func GetParamGP() (*big.Int, *big.Int) {
	p := new(big.Int).SetBytes([]byte("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea" +
		"63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a" +
		"637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d" +
		"39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca23732" +
		"7ffffffffffffffff"))
	g := p
	return p, g
}

func GetParamGP1() (*big.Int, *big.Int) {
	p := new(big.Int).SetBytes([]byte("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea" +
		"63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a" +
		"637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d" +
		"39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca23732" +
		"7ffffffffffffffff"))
	g := new(big.Int)
	g = g.Sub(p, new(big.Int).SetUint64(1))
	return p, g
}

func TestDHAlgEva_MITMAttack(t *testing.T) {
	dhA := new(DHAlg)
	dhB := new(DHAlg)
	pA, pB := MITMAttack(dhA, dhB, GetHardcodeParams)
	assert.EqualValues(t, pA, pB)
}

func TestMITMAttackG(t *testing.T) {
	tests := []struct {
		function params
	}{
		{GetParamG1},
		{GetParamGP},
		{GetParamGP1},
	}

	dhA := new(DHAlg)
	dhB := new(DHAlg)

	for _, tt := range tests {
		tf := tt.function
		t.Run("", func(t *testing.T) {
			pA, pB := MITMAttackG(dhA, dhB, tf)
			assert.NotEmpty(t, pA)
			assert.NotEmpty(t, pB)
			require.EqualValues(t, pA, pB)
		})
	}
}
