package all

// Import this file for side-effect to register all algorithms
import (
	_ "github.com/jaspeen/apikeyman/algo/ecdsa"
	_ "github.com/jaspeen/apikeyman/algo/eddsa"
	_ "github.com/jaspeen/apikeyman/algo/rsa"
	_ "github.com/jaspeen/apikeyman/algo/secp256k1"
)
