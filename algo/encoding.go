package algo

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log"
)

func KeyToBase64(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func Base64ToKey(base64Key string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(base64Key)
}

func PrivateKeyToPem(pk []byte, out io.Writer) {
	var pemBlock = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pk,
	}
	err := pem.Encode(out, pemBlock)
	if err != nil {
		log.Fatal(err)
	}
}

func PemToKey(pemBytes []byte) ([]byte, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("failed to decode pem")
	}
	return pemBlock.Bytes, nil
}

func PublicKeyToPem(pk []byte, out io.Writer) {
	var pemBlock = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pk,
	}
	err := pem.Encode(out, pemBlock)
	if err != nil {
		log.Fatal(err)
	}
}
