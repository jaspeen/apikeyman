package tests_test

import (
	"testing"

	"github.com/jaspeen/apikeyman/algo"
	_ "github.com/jaspeen/apikeyman/algo/all"
)

func TestGenSignVerify(t *testing.T) {
	for _, algName := range algo.GetSignAlgorithmNames() {
		t.Run(algName, func(t *testing.T) {
			alg := algo.GetSignAlgorithm(algName)
			keys, err := alg.Generate()
			if err != nil {
				t.Error(err)
			}
			testData := []byte("test data")
			signature, err := alg.Sign(keys.Private, testData)
			if err != nil {
				t.Error(err)
			}
			err = alg.ValidateSignature(keys.Public, signature, testData)
			if err != nil {
				t.Error(err)
			}
		})
	}
}
