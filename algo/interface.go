package algo

type DerKeys struct {
	// PKIX binary format
	Public []byte
	// PKCS8 binary format
	Private []byte
}

type SignAlgorithm interface {
	Name() string
	/*
	  Generate keypair in DER format.
	*/
	Generate() (DerKeys, error)
	/*
		  Validate data signature.
			publicKey should be in PKIX DER format
			signature should be in binary format
			Return null if signature is valid, error otherwise.
	*/
	ValidateSignature(publicKey []byte, signature []byte, data []byte) error
	/*
	  Sign the data. Private key should be in PKCS8 DER format.
	*/
	Sign(privateKey []byte, data []byte) ([]byte, error)
}

var signAlgorithms = make(map[string]SignAlgorithm)

func RegisterSignAlgorithm(alg SignAlgorithm) {
	signAlgorithms[alg.Name()] = alg
}

func GetSignAlgorithm(name string) SignAlgorithm {
	return signAlgorithms[name]
}

func GetSignAlgorithmNames() []string {
	var keys []string
	for k := range signAlgorithms {
		keys = append(keys, k)
	}
	return keys
}
