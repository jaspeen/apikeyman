package api

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jaspeen/apikeyman/algo"
	"github.com/jaspeen/apikeyman/db"
	"github.com/jaspeen/apikeyman/db/queries"
	"github.com/sqlc-dev/pqtype"
)

const MAX_EXTRA_SIZE = 2048

type createApiKeyRequest struct {
	Sub       string          `json:"sub"`
	Alg       string          `json:"alg"`
	Name      string          `json:"name"`
	ExpSec    int             `json:"exp_sec"`
	PublicKey string          `json:"publickey"`
	Extra     json.RawMessage `json:"extra"`
}

func (p *createApiKeyRequest) Validate() error {
	if p.Sub == "" {
		return errors.New("sub is required")
	}
	if p.PublicKey != "" && p.Alg == "" {
		return errors.New("'alg' is required to import public key")
	}
	if len(p.Sub) > 255 {
		return errors.New("'sub' exceeds maximum length of 255 characters")
	}
	if len(p.Name) > 255 {
		return errors.New("'name' exceeds maximum length of 255 characters")
	}

	if p.Extra != nil && len(p.Extra) > MAX_EXTRA_SIZE {
		return errors.New("extra data exceeds maximum size of 2048 bytes")
	}

	return nil
}

type createApiKeyResponse struct {
	ApiKey     string `json:"apikey"`
	PublicKey  string `json:"publickey,omitempty"`
	PrivateKey string `json:"privatekey,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func extractCreateParams(params *createApiKeyRequest, c *gin.Context) error {
	err := c.Bind(params)
	if err != nil {
		return err
	}
	return params.Validate()
}

func (a *Api) CreateApiKey(c *gin.Context) {
	var params createApiKeyRequest
	err := extractCreateParams(&params, c)
	if err != nil {
		slog.Debug(fmt.Sprintf("Failed to extract create params: %s", err))
		c.JSON(400, errorResponse{Error: "Invalid request"})
		return
	}

	var insertParams queries.InsertApiKeyParams
	insertParams.Sub = sql.NullString{String: params.Sub, Valid: true}
	insertParams.Name = sql.NullString{String: params.Name, Valid: params.Name != ""}
	if params.ExpSec > 0 {
		insertParams.Exp = sql.NullTime{Time: time.Now().Add(time.Second * time.Duration(params.ExpSec)), Valid: true}
	} else {
		insertParams.Exp = sql.NullTime{Time: time.Now().Add(a.Config.DefaultKeyExpiration), Valid: true}
	}

	if params.Extra != nil {
		insertParams.Extra = pqtype.NullRawMessage{RawMessage: params.Extra, Valid: true}
	}

	// import or generate public key
	var keys algo.DerKeys
	if params.Alg != "" {
		alg := algo.GetSignAlgorithm(params.Alg)
		if alg == nil {
			c.JSON(400, errorResponse{Error: "Invalid algorithm"})
			return
		}
		insertParams.Alg = queries.NullAlgType{AlgType: queries.AlgType(params.Alg), Valid: true}

		if params.PublicKey == "" {
			keys, err = alg.Generate()
			if err != nil {
				slog.Error(fmt.Sprintf("Failed to generate keypair: %s", err))
				c.JSON(500, errorResponse{Error: "Internal server error"})
				return
			}
		} else {
			// decode public key from PEM PKIX format
			publicKeyBlock, err := pem.Decode([]byte(params.PublicKey))
			if err != nil || publicKeyBlock == nil {
				c.JSON(400, errorResponse{Error: "Invalid public key"})
				return
			}
			keys.Public = publicKeyBlock.Bytes
		}
		insertParams.Key = keys.Public
	}

	// generate secret
	generatedSecret := algo.GenerateSecret()
	insertParams.Sec = algo.HashSecret(generatedSecret)

	id, err := db.Queries.InsertApiKey(c.Request.Context(), a.Db, insertParams)
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to insert api key: %s", err))
		c.JSON(500, errorResponse{Error: "Internal server error"})
		return
	}

	apiKey := ApiKey{Id: id, Secret: generatedSecret}
	encodedPublicKey := base64.StdEncoding.EncodeToString(keys.Public)
	var encodedPrivateKey string
	if keys.Private != nil {
		encodedPrivateKey = base64.StdEncoding.EncodeToString(keys.Private)
	}

	c.JSON(200,
		createApiKeyResponse{
			ApiKey:     apiKey.String(),
			PublicKey:  encodedPublicKey,
			PrivateKey: encodedPrivateKey,
		})
}

type listApiKeysRequest struct {
	Sub string `json:"sub"`
}

type ApiKeyResponse struct {
	Id    int64           `json:"id"`
	Sub   string          `json:"sub"`
	Name  string          `json:"name"`
	Alg   string          `json:"alg"`
	Key   string          `json:"key"`
	Exp   time.Time       `json:"exp"`
	Extra json.RawMessage `json:"extra"`
}

func (a *Api) ListApiKeys(c *gin.Context) {
	var req listApiKeysRequest
	err := c.Bind(&req)
	if err != nil || req.Sub == "" {
		respondInvalidRequest(c)
		return
	}

	sub := sql.NullString{String: req.Sub, Valid: true}
	var res []ApiKeyResponse

	keys, err := db.Queries.SearchApiKeys(c.Request.Context(), a.Db, sub)
	if err != nil {
		c.JSON(500, errorResponse{Error: "Internal server error"})
		return
	}
	for _, key := range keys {
		res = append(res, ApiKeyResponse{
			Id:   key.ID,
			Sub:  key.Sub.String,
			Name: key.Name.String,
			Alg:  string(key.Alg.AlgType),
			Key:  algo.KeyToBase64(key.Key),
			Exp:  key.Exp.Time,
		})
	}

	c.JSON(200, res)
}

func (a *Api) GetApiKey(c *gin.Context) {
	apiKey, err := ParseApiKey(c.Param("apikey"))
	if err != nil {
		a.Log.Error(fmt.Sprintf("Failed to parse api key '%s': %s", c.Param("apikey"), err))
		c.JSON(400, errorResponse{Error: "Invalid API key"})
		return
	}

	if a.Log.Enabled(c.Request.Context(), slog.LevelDebug) {
		slog.Debug("get", "id", apiKey.Id)
	}

	key, err := db.Queries.GetApiKey(c.Request.Context(), a.Db, apiKey.Id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(404, errorResponse{Error: "API key not found"})
		} else {
			slog.Error(fmt.Sprintf("Failed to load api key: %s", err))
			c.JSON(500, errorResponse{Error: "Internal server error"})
		}
		return
	}

	c.JSON(200, ApiKeyResponse{
		Id:    key.ID,
		Sub:   key.Sub.String,
		Name:  key.Name.String,
		Alg:   string(key.Alg.AlgType),
		Key:   algo.KeyToBase64(key.Key),
		Exp:   key.Exp.Time,
		Extra: key.Extra.RawMessage,
	})
}
