package algo

import "errors"

var ErrInvalidKeyType = errors.New("invalid key type")
var ErrKeyMustBePEMEncoded = errors.New("key must be PEM encoded")
var ErrHashUnavailable = errors.New("hash function not available")
var ErrInvalidSignature = errors.New("invalid signature")
