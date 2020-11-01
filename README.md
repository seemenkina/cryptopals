# Cryptopals solution

Solution [Cryptopals cryptographic challenges](https://cryptopals.com/) in golang.

## Run challenges in set 5 

Start tests file for DH attack from challenge 5 (33-35)

Test to check the implementation of DH algorithm
```
$ go test ./set5 -run TestDiffieHellman TestDHEncrypt
$ go test ./set5 -run TestDHEncrypt
```

Test to check the implementation a MITM key-fixing attack on Diffie-Hellman with parameter injection
```
$ go test ./set5 -run TestDHAlgEva_MITMAttack
```

Test to check the implementation DH with negotiated groups, and break with malicious "g" parameters

```
$ go test ./set5 -run TestMITMAttackG
```