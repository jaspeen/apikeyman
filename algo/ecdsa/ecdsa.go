package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"github.com/jaspeen/apikeyman/algo"
)

type ECDSAAlgorithm struct {
	name string
	hash crypto.Hash
}

func (a *ECDSAAlgorithm) Name() string {
	return a.name
}

func (a *ECDSAAlgorithm) Sign(privateKey []byte, data []byte) ([]byte, error) {
	var parsedKey interface{}
	var err error
	if parsedKey, err = x509.ParsePKCS8PrivateKey(privateKey); err != nil {
		return nil, err
	}

	var ecdsaKey *ecdsa.PrivateKey
	var ok bool

	// Validate type of key
	if ecdsaKey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, algo.ErrInvalidKeyType
	}

	// Create the hasher
	if !a.hash.Available() {
		return nil, algo.ErrHashUnavailable
	}

	hasher := a.hash.New()
	hasher.Write(data)

	// Sign the string and return the encoded bytes
	return ecdsa.SignASN1(rand.Reader, ecdsaKey, hasher.Sum(nil))
}

func (a *ECDSAAlgorithm) ValidateSignature(publicKey []byte, signature []byte, data []byte) error {
	// Parse the key
	var parsedKey interface{}
	var err error
	if parsedKey, err = x509.ParsePKIXPublicKey(publicKey); err != nil {
		return err
	}

	var pkey *ecdsa.PublicKey
	var ok bool
	// Validate type of key
	if pkey, ok = parsedKey.(*ecdsa.PublicKey); !ok {
		return algo.ErrInvalidKeyType
	}

	// Create the hasher
	if !a.hash.Available() {
		return algo.ErrHashUnavailable
	}

	hasher := a.hash.New()
	hasher.Write(data)

	// Verify the signature
	if !ecdsa.VerifyASN1(pkey, hasher.Sum(nil), signature) {
		return algo.ErrInvalidSignature
	}

	return nil
}

func (a *ECDSAAlgorithm) Generate() (algo.DerKeys, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return algo.DerKeys{}, err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return algo.DerKeys{}, err
	}

	// Marshal the public key to PEM format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return algo.DerKeys{}, err
	}

	return algo.DerKeys{Public: pubKeyBytes, Private: keyBytes}, nil
}

func init() {
	algo.RegisterSignAlgorithm(&ECDSAAlgorithm{name: "ES256", hash: crypto.SHA256})
}
