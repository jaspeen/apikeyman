package secp256k1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/dustinxie/ecc"
	"golang.org/x/crypto/cryptobyte"
)

var secp256k1Oid = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

const ecPrivKeyVersion = 1

// pkcs8 reflects an ASN.1, PKCS #8 PrivateKey. See
// ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-8/pkcs-8v1_2.asn
// and RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes omitted.
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type pkixPublicKey struct {
	Algo      pkix.AlgorithmIdentifier
	BitString asn1.BitString
}

type publicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func Generate() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
}

func marshalECPrivateKeyWithOID(key *ecdsa.PrivateKey, oid asn1.ObjectIdentifier) ([]byte, error) {
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("invalid elliptic key public key")
	}
	privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.D.FillBytes(privateKey),
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}

// marshal only secp256k1 ecdsa key, use x509.MarshalPKCS8PrivateKey for others
func MarshalPKCS8PrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	oidBytes, err := asn1.Marshal(secp256k1Oid)
	if err != nil {
		return nil, errors.New("x509: failed to marshal curve OID: " + err.Error())
	}
	ecMarshalledKey, err := marshalECPrivateKeyWithOID(key, secp256k1Oid)
	if err != nil {
		return nil, errors.New("x509: failed to marshal EC private key: " + err.Error())
	}
	return asn1.Marshal(pkcs8{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyECDSA,
			Parameters: asn1.RawValue{
				FullBytes: oidBytes,
			},
		},
		PrivateKey: ecMarshalledKey,
	})
}

func parseECPrivateKey(namedCurveOID *asn1.ObjectIdentifier, der []byte) (key *ecdsa.PrivateKey, err error) {
	var privKey ecPrivateKey
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("x509: failed to parse EC private key: " + err.Error())
	}
	if privKey.Version != ecPrivKeyVersion {
		return nil, fmt.Errorf("x509: unknown EC private key version %d", privKey.Version)
	}

	if namedCurveOID != nil && !namedCurveOID.Equal(secp256k1Oid) {
		return nil, errors.New("x509: invalid secp256k1 OID")
	}

	curve := ecc.P256k1()

	k := new(big.Int).SetBytes(privKey.PrivateKey)
	curveOrder := curve.Params().N
	if k.Cmp(curveOrder) >= 0 {
		return nil, errors.New("x509: invalid elliptic curve private key value")
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = curve
	priv.D = k

	privateKey := make([]byte, (curveOrder.BitLen()+7)/8)

	// Some private keys have leading zero padding. This is invalid
	// according to [SEC1], but this code will ignore it.
	for len(privKey.PrivateKey) > len(privateKey) {
		if privKey.PrivateKey[0] != 0 {
			return nil, errors.New("x509: invalid private key length")
		}
		privKey.PrivateKey = privKey.PrivateKey[1:]
	}

	// Some private keys remove all leading zeros, this is also invalid
	// according to [SEC1] but since OpenSSL used to do this, we ignore
	// this too.
	copy(privateKey[len(privateKey)-len(privKey.PrivateKey):], privKey.PrivateKey)
	priv.X, priv.Y = curve.ScalarBaseMult(privateKey)

	return priv, nil
}

func ParsePKCS8PrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	var privKey pkcs8
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, err
	}
	bytes := privKey.Algo.Parameters.FullBytes
	namedCurveOID := new(asn1.ObjectIdentifier)
	if _, err := asn1.Unmarshal(bytes, namedCurveOID); err != nil {
		namedCurveOID = nil
	}

	key, err := parseECPrivateKey(namedCurveOID, privKey.PrivateKey)
	if err != nil {
		return nil, errors.New("x509: failed to parse EC private key embedded in PKCS#8: " + err.Error())
	}
	return key, nil
}

func MarshalPKIXPublicKey(key *ecdsa.PublicKey) ([]byte, error) {
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, errors.New("x509: invalid elliptic curve public key")
	}
	publicKeyBytes := elliptic.Marshal(key.Curve, key.X, key.Y)
	paramBytes, err := asn1.Marshal(secp256k1Oid)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(pkixPublicKey{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyECDSA,
			Parameters: asn1.RawValue{FullBytes: paramBytes},
		},
		BitString: asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		},
	})
}

func ParsePKIXPublicKey(der []byte) (*ecdsa.PublicKey, error) {
	var pkixPublicKey publicKeyInfo
	if rest, err := asn1.Unmarshal(der, &pkixPublicKey); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("x509: trailing data after ASN.1 of public-key")
	}
	if !pkixPublicKey.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		return nil, errors.New("x509: invalid ECDSA public key OID")
	}
	alignedDer := cryptobyte.String(pkixPublicKey.PublicKey.RightAlign())
	paramsDer := cryptobyte.String(pkixPublicKey.Algorithm.Parameters.FullBytes)
	namedCurveOID := new(asn1.ObjectIdentifier)
	if !paramsDer.ReadASN1ObjectIdentifier(namedCurveOID) {
		return nil, errors.New("x509: invalid ECDSA parameters")
	}

	if !namedCurveOID.Equal(secp256k1Oid) {
		return nil, errors.New("x509: invalid secp256k1 OID")
	}

	curve := ecc.P256k1()

	x, y := elliptic.Unmarshal(curve, alignedDer)
	if x == nil {
		return nil, errors.New("x509: failed to unmarshal elliptic curve point")
	}
	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return pub, nil
}
