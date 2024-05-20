package secp256k1_test

import (
	"testing"

	"github.com/jaspeen/apikeyman/algo"
	_ "github.com/jaspeen/apikeyman/algo/secp256k1"
	"github.com/jaspeen/apikeyman/algo/tests"
)

func TestSignVerify(t *testing.T) {
	t.Run("ES256K", func(t *testing.T) {
		tests.RunSignVerifyTest(t, algo.GetSignAlgorithm("ES256K"),
			`-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEUunPSedeC7dTx8Er9crdpcBAnguQPDDr
f639NVdqnHle0zyNdP47DQtRG8V+kBm0lAvPRicZhaCC75TNHXHGZg==
-----END PUBLIC KEY-----							
`,
			`-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgCfxFW+8V/PVIxYFQEAzD
0+van8F5PXHSGjspMqR4+pGhRANCAARS6c9J514Lt1PHwSv1yt2lwECeC5A8MOt/
rf01V2qceV7TPI10/jsNC1EbxX6QGbSUC89GJxmFoILvlM0dccZm
-----END PRIVATE KEY-----									
`,
			"MEQCIBWRYlOncSHV5QH4klMcJeH33ZyMkzaLZYvo48Obm88PAiA8QOkzUlp/sjeT1unzfUn+NXfb1VTH8RXV5j6U70MaEg==",
			"test data")
	})
}
