package eddsa

import (
	"crypto/ed25519"
	"crypto/x509"

	"github.com/jaspeen/apikeyman/algo"
)

type EdDSAAlgorithm struct {
	name string
}

func (a *EdDSAAlgorithm) Name() string {
	return a.name
}

func (a *EdDSAAlgorithm) Sign(privateKey []byte, data []byte) ([]byte, error) {
	var parsedKey interface{}
	var err error
	if parsedKey, err = x509.ParsePKCS8PrivateKey(privateKey); err != nil {
		return nil, err
	}

	var edKey ed25519.PrivateKey
	var ok bool

	// Validate type of key
	if edKey, ok = parsedKey.(ed25519.PrivateKey); !ok {
		return nil, algo.ErrInvalidKeyType
	}

	// Sign the string and return the encoded bytes
	return ed25519.Sign(edKey, data), nil
}

func (a *EdDSAAlgorithm) ValidateSignature(publicKey []byte, signature []byte, data []byte) error {
	var err error

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(publicKey); err != nil {
		return err
	}

	var pkey ed25519.PublicKey
	var ok bool
	// Validate type of key
	if pkey, ok = parsedKey.(ed25519.PublicKey); !ok {
		return algo.ErrInvalidKeyType
	}

	if !ed25519.Verify(pkey, data, signature) {
		return algo.ErrInvalidSignature
	}

	return nil
}

func (a *EdDSAAlgorithm) Generate() (algo.DerKeys, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	derPrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return algo.DerKeys{}, err
	}
	derPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return algo.DerKeys{}, err
	}

	return algo.DerKeys{
		Public:  derPublicKey,
		Private: derPrivateKey,
	}, nil
}

func init() {
	algo.RegisterSignAlgorithm(&EdDSAAlgorithm{name: "EdDSA"})
}
