package tests

import (
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/jaspeen/apikeyman/algo"
)

func mustDecodePem(pemStr string) []byte {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		panic("failed to decode pem")
	}
	return block.Bytes
}

func prepareTestData(publicKey string, privateKey string, signature string, data string) (publicKeyBytes []byte, privateKeyBytes []byte, signatureBytes []byte, dataBytes []byte) {
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		panic(err)
	}
	return mustDecodePem(publicKey), mustDecodePem(privateKey), signatureBytes, []byte(data)
}

func RunSignVerifyTest(t *testing.T, alg algo.SignAlgorithm, publicKey string, privateKey string, signature string, data string) {
	publicKeyBytes, privateKeyBytes, signatureBytes, dataBytes := prepareTestData(publicKey, privateKey, signature, data)

	t.Run("sign_validate", func(t *testing.T) {
		sig, err := alg.Sign(privateKeyBytes, dataBytes)
		if err != nil {
			t.Error(err)
		}
		err = alg.ValidateSignature(publicKeyBytes, sig, dataBytes)
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("validate", func(t *testing.T) {
		err := alg.ValidateSignature(publicKeyBytes, signatureBytes, dataBytes)
		if err != nil {
			t.Error(err)
		}
	})
}
