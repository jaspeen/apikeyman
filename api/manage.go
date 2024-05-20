package api

import (
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jaspeen/apikeyman/algo"
	"github.com/jaspeen/apikeyman/db"
	"github.com/jaspeen/apikeyman/db/queries"
)

type createParams struct {
	Sub         string `json:"sub"`
	Alg         string `json:"alg"`
	Name        string `json:"name"`
	DurationMin int    `json:"duration_min"`
	PublicKey   string `json:"publickey"`
}

func (p *createParams) Validate() error {
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
	return nil
}

type createResult struct {
	ApiKey     string `json:"apikey"`
	PublicKey  string `json:"publickey,omitempty"`
	PrivateKey string `json:"privatekey,omitempty"`
}

type errorResponse struct {
	Error string `json:"error"`
}

func extractCreateParams(params *createParams, c *gin.Context) error {
	err := c.Bind(params)
	if err != nil {
		return err
	}
	return params.Validate()
}

func (a *Api) CreateApiKey(c *gin.Context) {
	var params createParams
	err := extractCreateParams(&params, c)
	if err != nil {
		slog.Debug(fmt.Sprintf("Failed to extract create params: %s", err))
		c.JSON(400, errorResponse{Error: "Invalid request"})
		return
	}
	slog.Debug("create", "params", params)

	var insertParams queries.InsertApiKeyParams
	insertParams.Sub = sql.NullString{String: params.Sub, Valid: true}
	insertParams.Name = sql.NullString{String: params.Name, Valid: params.Name != ""}
	if params.DurationMin > 0 {
		insertParams.Exp = sql.NullTime{Time: time.Now().Add(time.Minute * time.Duration(params.DurationMin))}
	}

	// import or generate public key
	//var alg algo.SignAlgorithm
	var keys algo.DerKeys
	if params.Alg != "" {
		alg := algo.GetSignAlgorithm(params.Alg)
		if alg == nil {
			c.JSON(400, errorResponse{Error: "Invalid algorithm"})
			return
		}

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
		slog.Debug(fmt.Sprintf("Public key: %s", base64.StdEncoding.EncodeToString(insertParams.Key)))
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

	c.JSON(200,
		createResult{
			ApiKey:     apiKey.String(),
			PublicKey:  base64.StdEncoding.EncodeToString(insertParams.Key),
			PrivateKey: base64.StdEncoding.EncodeToString(keys.Private),
		})
}

func (a *Api) ListApiKeys(c *gin.Context) {
	sub := sql.NullString{String: c.PostForm("sub")}

	keys, err := db.Queries.SearchApiKeys(c.Request.Context(), a.Db, sub)
	if err != nil {
		c.JSON(500, errorResponse{Error: "Internal server error"})
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
			c.JSON(500, errorResponse{Error: "Internal server error"})
		}
		return
	}

	c.JSON(200, key)
}
