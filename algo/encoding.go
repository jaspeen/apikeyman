package algo

import (
	"encoding/pem"
	"io"
	"log"
)

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
