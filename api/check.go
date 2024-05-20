package api

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jaspeen/apikeyman/algo"
	"github.com/jaspeen/apikeyman/db"
	"github.com/jaspeen/apikeyman/db/queries"
)

func (a *Api) checkAndGetApiKeyData(c *gin.Context) (*queries.GetApiKeyForVerifyRow, error) {
	apiKeyHeaderName := c.DefaultQuery("apikey_name", API_KEY_DEFAULT_HEADER)
	apiKeyString := c.Request.Header.Get(apiKeyHeaderName)
	apiKey, err := ParseApiKey(apiKeyString)

	if err != nil {
		return nil, err
	}

	secretHash := algo.HashSecret(apiKey.Secret)

	apiKeyData, err := db.Queries.GetApiKeyForVerify(c.Request.Context(), a.Db, apiKey.Id)

	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(secretHash, apiKeyData.Sec) != 1 {
		return nil, ErrUnauthorized
	}

	return &apiKeyData, nil
}

func (a *Api) Check(c *gin.Context) {
	apiKeyData, err := a.checkAndGetApiKeyData(c)
	if err != nil {
		respondUnauthorized(c)
	} else {
		c.JSON(200, gin.H{
			"subject": apiKeyData.Sub.String,
		})
	}
}

func (a *Api) Validate(c *gin.Context) {
	apiKeyData, err := a.checkAndGetApiKeyData(c)
	if err != nil {
		respondUnauthorized(c)
		return
	}

	signature := c.Request.Header.Get(SIGNATURE_DEFAULT_HEADER)
	timestampStr := c.Request.Header.Get(TIMESTAMP_DEFAULT_HEADER)

	i, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		slog.Error(fmt.Sprintf("Invalid timestamp: %s", timestampStr))
		respondUnauthorized(c)
		return
	}
	timestamp := time.Unix(i, 0)

	if time.Since(timestamp) > 5*time.Minute {
		slog.Error(fmt.Sprintf("Expired timestamp: %s", timestampStr))
		respondUnauthorized(c)
		return
	}

	data, err := c.GetRawData()
	if err != nil {
		c.JSON(500, errorResponse{Error: "Internal server error"})
		return
	}

	alg := algo.GetSignAlgorithm(string(apiKeyData.Alg.AlgType))
	if alg == nil {
		slog.Error(fmt.Sprintf("Invalid algorithm: %s", apiKeyData.Alg.AlgType))
		c.JSON(400, errorResponse{Error: "Invalid request"})
		return
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		c.JSON(400, errorResponse{Error: "Invalid signature"})
		return
	}

	err = alg.ValidateSignature(signatureBytes, append(data, []byte(timestampStr)...), apiKeyData.Key)

	if err != nil {
		respondUnauthorized(c)
		return
	}

	c.JSON(200, gin.H{
		"subject": apiKeyData.Sub.String,
	})
}
