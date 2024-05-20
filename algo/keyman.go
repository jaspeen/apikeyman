package algo

import (
	"crypto/rand"
	"crypto/sha256"
	"log"

	"github.com/shengdoushi/base58"
)

func GenerateKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("Failed to generate key: %s", err)
	}
	return key
}

func HashKey(key []byte) []byte {
	var hash = sha256.Sum256(key)
	return hash[:]
}

func EncodeKey(key []byte) string {
	return base58.Encode(key, base58.RippleAlphabet)
}

func DecodeKey(key string) ([]byte, error) {
	return base58.Decode(key, base58.RippleAlphabet)
}
