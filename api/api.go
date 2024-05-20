package api

import (
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jaspeen/apikeyman/algo"
	"github.com/jaspeen/apikeyman/db"
	"github.com/jaspeen/apikeyman/db/queries"
)

const (
	API_KEY_DEFAULT_HEADER   = "X-API-Key"
	SIGNATURE_DEFAULT_HEADER = "X-Signature"
	TIMESTAMP_DEFAULT_HEADER = "X-Timestamp"
)

type Config struct {
	ApiKeyHeaderName     string
	ApiKeyQueryParamName string
	SignatureHeaderName  string
	SignatureQueryParam  string
	TimestampHeaderName  string
	TimestampQueryParam  string
	TimestampExpiration  time.Duration
}

func extractIdAndSecret(apiKey string) (int64, string, error) {
	parts := strings.Split(apiKey, ":")
	if len(parts) != 2 {
		return 0, "", errors.New("invalid API key")
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	return id, parts[1], err
}

type Api struct {
	Log    *slog.Logger
	Db     *sql.DB
	Config Config
}

func (a *Api) checkAndGetApiKeyData(c *gin.Context) (*queries.GetApiKeyForVerifyRow, error) {
	apiKeyHeaderName := c.DefaultQuery("apikey_name", API_KEY_DEFAULT_HEADER)
	apiKey := c.Request.Header.Get(apiKeyHeaderName)
	id, secret, err := extractIdAndSecret(apiKey)

	if err != nil {
		return nil, err
	}

	secretBytes, err := algo.DecodeKey(secret)
	if err != nil {
		return nil, err
	}

	secretHash := algo.HashKey(secretBytes)

	apiKeyData, err := db.Queries.GetApiKeyForVerify(c.Request.Context(), a.Db, id)

	if err != nil {
		return nil, err
	}

	if subtle.ConstantTimeCompare(secretHash, apiKeyData.Sec) != 1 {
		return nil, errors.New("Unauthorized")
	}

	return &apiKeyData, nil
}

func (a *Api) Check(c *gin.Context) {
	apiKeyData, err := a.checkAndGetApiKeyData(c)
	if err != nil {
		c.JSON(401, gin.H{"msg": "Unauthorized"})
	} else {
		c.JSON(200, gin.H{
			"subject": apiKeyData.Sub.String,
		})
	}
}

func (a *Api) Validate(c *gin.Context) {
	apiKeyData, err := a.checkAndGetApiKeyData(c)
	if err != nil {
		c.JSON(401, errorResponse{Error: "Unauthorized"})
		return
	}

	signature := c.Request.Header.Get(SIGNATURE_DEFAULT_HEADER)
	timestampStr := c.Request.Header.Get(TIMESTAMP_DEFAULT_HEADER)

	i, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		slog.Error(fmt.Sprintf("Invalid timestamp: %s", timestampStr))
		c.JSON(401, errorResponse{Error: "Unauthorized"})
		return
	}
	timestamp := time.Unix(i, 0)

	if time.Since(timestamp) > 5*time.Minute {
		slog.Error(fmt.Sprintf("Expired timestamp: %s", timestampStr))
		c.JSON(401, errorResponse{Error: "Unauthorized"})
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
		c.JSON(401, errorResponse{Error: "Unauthorized"})
		return
	}

	c.JSON(200, gin.H{
		"subject": apiKeyData.Sub.String,
	})
}

type createParams struct {
	Sub         string `json:"sub"`
	Alg         string `json:"alg"`
	Name        string `json:"name"`
	DurationMin int    `json:"duration_min"`
	PublicKey   string `json:"public_key"`
}

type createResult struct {
	ApiKey    string `json:"apikey"`
	PublicKey string `json:"publickey"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func extractCreateParams(params *createParams, c *gin.Context) error {
	return c.Bind(params)
}

func (a *Api) CreateApiKey(c *gin.Context) {
	var params createParams
	err := extractCreateParams(&params, c)
	if err != nil {
		c.JSON(400, errorResponse{Error: "Invalid request"})
		return
	}

	var insertParams queries.InsertApiKeyParams
	insertParams.Sub = sql.NullString{String: params.Sub}
	insertParams.Name = sql.NullString{String: params.Name}
	insertParams.Exp = time.Now().Add(time.Minute * time.Duration(params.DurationMin))

	var alg algo.SignAlgorithm
	if params.Alg != "" {
		alg = algo.GetSignAlgorithm(params.Alg)
		if alg == nil {
			c.JSON(400, errorResponse{Error: "Invalid algorithm"})
			return
		}

		if params.PublicKey == "" {
			keypair, err := alg.Generate()
			if err != nil {
				slog.Error(fmt.Sprintf("Failed to generate keypair: %s", err))
				c.JSON(500, errorResponse{Error: "Internal server error"})
				return
			}
			insertParams.Key = keypair.Public
		} else {
			publicKeyBlock, err := pem.Decode([]byte(params.PublicKey))
			if err != nil || publicKeyBlock == nil {
				c.JSON(400, errorResponse{Error: "Invalid public key"})
				return
			}
			insertParams.Key = publicKeyBlock.Bytes
		}
	}

	id, err := db.Queries.InsertApiKey(c.Request.Context(), a.Db, insertParams)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to insert api key: %s", err))
		c.JSON(500, gin.H{"msg": "Internal server error"})
		return
	}

	c.JSON(200,
		createResult{
			ApiKey:    fmt.Sprintf("%d:%s", id, base64.StdEncoding.EncodeToString(insertParams.Key)),
			PublicKey: base64.StdEncoding.EncodeToString(insertParams.Key),
		})
}

func (a *Api) ListApiKeys(c *gin.Context) {
	sub := sql.NullString{String: c.PostForm("sub")}

	keys, err := db.Queries.SearchApiKeys(c.Request.Context(), a.Db, sub)
	if err != nil {
		c.JSON(500, gin.H{"msg": "Internal server error"})
		return
	}

	c.JSON(200, keys)
}

func (a *Api) GetApiKey(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("apikey"), 10, 64)
	if err != nil {
		c.JSON(400, errorResponse{Error: "Invalid API key"})
		return
	}

	key, err := db.Queries.GetApiKey(c.Request.Context(), a.Db, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, errorResponse{Error: "API key not found"})
		} else {
			slog.Error(fmt.Sprintf("Failed to load api key: %s", err))
			c.JSON(500, gin.H{"msg": "Internal server error"})
		}
		return
	}

	c.JSON(200, key)
}

func (a *Api) Routes(prefix string) *gin.Engine {
	router := gin.Default()
	v1 := router.Group(prefix)

	// check api key exist and not expired
	v1.POST("/check", a.Check)

	// check api key and validate body signature
	// only for POST, PUT, PATCH
	v1.POST("/validate", a.Validate)

	manage := v1.Group("/apikeys")
	// create new api key
	manage.POST("/", a.CreateApiKey)
	// list all api keys filtering by sub, exp and alg
	manage.POST("/search", a.ListApiKeys)
	// get api key by id
	manage.GET("/{apikey}", a.GetApiKey)

	return router
}
