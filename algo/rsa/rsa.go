package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/jaspeen/apikeyman/algo"
)

type RSAAlgorithm struct {
	name string
	hash crypto.Hash
}

func (a *RSAAlgorithm) Name() string {
	return a.name
}

func (a *RSAAlgorithm) Sign(privateKey []byte, data []byte) ([]byte, error) {
	var parsedKey interface{}
	var err error
	if parsedKey, err = x509.ParsePKCS8PrivateKey(privateKey); err != nil {
		return nil, err
	}

	var rsaKey *rsa.PrivateKey
	var ok bool

	// Validate type of key
	if rsaKey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, algo.ErrInvalidKeyType
	}

	// Create the hasher
	if !a.hash.Available() {
		return nil, algo.ErrHashUnavailable
	}

	hasher := a.hash.New()
	hasher.Write(data)

	// Sign the string and return the encoded bytes
	if sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, a.hash, hasher.Sum(nil)); err == nil {
		return sigBytes, nil
	} else {
		return nil, err
	}
}

func (a *RSAAlgorithm) ValidateSignature(publicKey []byte, signature []byte, data []byte) error {
	var parsedKey interface{}
	var err error
	if parsedKey, err = x509.ParsePKIXPublicKey(publicKey); err != nil {
		return err
	}

	var rsaKey *rsa.PublicKey
	var ok bool

	// Validate type of key
	if rsaKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return algo.ErrInvalidKeyType
	}

	// Create the hasher
	if !a.hash.Available() {
		return algo.ErrHashUnavailable
	}

	hasher := a.hash.New()
	hasher.Write(data)

	// Verify the signature
	if err := rsa.VerifyPKCS1v15(rsaKey, a.hash, hasher.Sum(nil), signature); err != nil {
		return err
	}

	return nil
}

func (a *RSAAlgorithm) Generate() (algo.DerKeys, error) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	derPublicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return algo.DerKeys{}, err
	}
	derPrivateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return algo.DerKeys{}, err
	}

	return algo.DerKeys{
		Public:  derPublicKey,
		Private: derPrivateKey,
	}, nil

	//Public:  pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: derPublicKey}),
	//	Private: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
}

func init() {
	algo.RegisterSignAlgorithm(&RSAAlgorithm{name: "RS256", hash: crypto.SHA256})
	algo.RegisterSignAlgorithm(&RSAAlgorithm{name: "RS512", hash: crypto.SHA512})
}
