package eddsa_test

import (
	"testing"

	"github.com/jaspeen/apikeyman/algo"
	_ "github.com/jaspeen/apikeyman/algo/eddsa"
	"github.com/jaspeen/apikeyman/algo/tests"
)

func TestSignVerify(t *testing.T) {
	t.Run("EdDSA", func(t *testing.T) {
		tests.RunSignVerifyTest(t, algo.GetSignAlgorithm("EdDSA"),
			`-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAfNCMRnPtoM8dcr86r/fh4fcWO1INvGntwI77IM0JHO8=
-----END PUBLIC KEY-----			
`,
			`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIO7yeXDDi7Y+mJE+y1mpb793TDRyGwCvu+8qNWWXs8tL
-----END PRIVATE KEY-----						
`,
			"7U9hkI+T3gYyBLY/3qmH0IIoW4g1el4IDlINhoTjjyWkMeSLE+GXvCxVWubuXG8LQXwal35KJn/o7hsOEKljAw==",
			"test data")
	})
}
