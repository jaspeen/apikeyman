package algo

import (
	"crypto/rand"
	"crypto/sha256"
	"log"

	"github.com/shengdoushi/base58"
)

func GenerateSecret() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate key: %s", err)
	}
	return key
}

func HashSecret(secret []byte) []byte {
	var hash = sha256.Sum256(secret)
	return hash[:]
}

func EncodeSecret(secret []byte) string {
	return base58.Encode(secret, base58.RippleAlphabet)
}

func DecodeSecret(secret string) ([]byte, error) {
	return base58.Decode(secret, base58.RippleAlphabet)
}
