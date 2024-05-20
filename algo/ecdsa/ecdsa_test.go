package ecdsa_test

import (
	"testing"

	"github.com/jaspeen/apikeyman/algo"
	_ "github.com/jaspeen/apikeyman/algo/ecdsa"
	"github.com/jaspeen/apikeyman/algo/tests"
)

func TestSignVerify(t *testing.T) {
	t.Run("ES256", func(t *testing.T) {
		tests.RunSignVerifyTest(t, algo.GetSignAlgorithm("ES256"),
			`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGKnp/3zNFh2AGd8HcJkqJY9V0s/K
9FnlrDzhSajKIGWMqwXt9PejmaqVVN/qgmYI1kNd1pcxUX6kPl5PwyEUcw==
-----END PUBLIC KEY-----					
`,
			`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQglITa2ySHh9JJerGb
HDyeRfOFa5dpKy1Y2vpg/kxv6R2hRANCAAQYqen/fM0WHYAZ3wdwmSolj1XSz8r0
WeWsPOFJqMogZYyrBe3096OZqpVU3+qCZgjWQ13WlzFRfqQ+Xk/DIRRz
-----END PRIVATE KEY-----							
`,
			"MEQCIEtmxtkaDEAo5L4g/WBCpD/8KIswpBTnt7m7HJHdzePfAiBzrpR4szXzMPbJqxMFGp325aCOSVzk06A6PfUgvWDzDw==",
			"test data")
	})
}
