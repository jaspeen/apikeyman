package secp256k1

import (
	"crypto"
	"crypto/rand"

	"github.com/dustinxie/ecc"
	"github.com/jaspeen/apikeyman/algo"
)

type Secp256k1Algorithm struct {
	hash crypto.Hash
}

func (a *Secp256k1Algorithm) Name() string {
	return "ES256K"
}

func (a *Secp256k1Algorithm) Generate() (algo.DerKeys, error) {
	key, err := Generate()
	if err != nil {
		return algo.DerKeys{}, err
	}

	privateKeyBytes, err := MarshalPKCS8PrivateKey(key)
	if err != nil {
		return algo.DerKeys{}, err
	}

	publicKeyBytes, err := MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return algo.DerKeys{}, err
	}

	return algo.DerKeys{
		Private: privateKeyBytes,
		Public:  publicKeyBytes,
	}, nil
}

func (a *Secp256k1Algorithm) Sign(privateKey []byte, data []byte) ([]byte, error) {
	key, err := ParsePKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	// Create the hasher
	if !a.hash.Available() {
		return nil, algo.ErrHashUnavailable
	}

	hasher := a.hash.New()
	hasher.Write(data)

	// Sign the string and return the encoded bytes
	return ecc.SignASN1(rand.Reader, key, hasher.Sum(nil))
}

func (a *Secp256k1Algorithm) ValidateSignature(publicKey []byte, signature []byte, data []byte) error {
	key, err := ParsePKIXPublicKey(publicKey)
	if err != nil {
		return err
	}

	// Create the hasher
	if !a.hash.Available() {
		return algo.ErrHashUnavailable
	}

	hasher := a.hash.New()
	hasher.Write(data)

	// Verify signature
	if !ecc.VerifyASN1(key, hasher.Sum(nil), signature) {
		return algo.ErrInvalidSignature
	}
	return nil
}

func init() {
	algo.RegisterSignAlgorithm(&Secp256k1Algorithm{hash: crypto.SHA256})
}
