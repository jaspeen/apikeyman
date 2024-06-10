package api

import (
	"database/sql"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jaspeen/apikeyman/algo"
	"github.com/jaspeen/apikeyman/db/queries"
	"github.com/jellydator/ttlcache/v3"
)

const (
	API_KEY_DEFAULT_HEADER   = "X-API-KEY"
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
	DefaultKeyExpiration time.Duration
	CacheMaxSize         uint64
	CacheTTL             time.Duration
}

var ErrUnauthorized = errors.New("Unauthorized")
var ErrInvalidApiKey = errors.New("Invalid API key")

func respondUnauthorized(c *gin.Context) {
	c.JSON(401, gin.H{"error": "Unauthorized"})
}

func respondInvalidRequest(c *gin.Context) {
	c.JSON(400, gin.H{"error": "Invalid request"})
}

type ApiKey struct {
	Id     int64
	Secret []byte
}

func (a *ApiKey) String() string {
	return strconv.FormatInt(a.Id, 10) + ":" + algo.EncodeSecret(a.Secret)
}

func extractIdAndSecret(apiKey string) (int64, string, error) {
	parts := strings.Split(apiKey, ":")
	if len(parts) != 2 {
		return 0, "", ErrInvalidApiKey
	}
	id, err := strconv.ParseInt(parts[0], 10, 64)
	return id, parts[1], err
}

func ParseApiKey(apiKey string) (*ApiKey, error) {
	id, secret, err := extractIdAndSecret(apiKey)
	if err != nil {
		return nil, err
	}
	secretBytes, err := algo.DecodeSecret(secret)
	if err != nil {
		return nil, err
	}
	return &ApiKey{Id: id, Secret: secretBytes}, nil
}

type Api struct {
	Log    *slog.Logger
	Db     *sql.DB
	Config Config
	cache  *ttlcache.Cache[string, *queries.GetApiKeyForVerifyRow]
}

func (a *Api) NewApi(log *slog.Logger, db *sql.DB, config Config) (*Api, error) {
	var cache *ttlcache.Cache[string, *queries.GetApiKeyForVerifyRow]
	if config.CacheMaxSize > 0 {
		cache = ttlcache.New(
			ttlcache.WithTTL[string, *queries.GetApiKeyForVerifyRow](config.CacheTTL),
			ttlcache.WithCapacity[string, *queries.GetApiKeyForVerifyRow](config.CacheMaxSize),
		)
	}
	return &Api{Log: log, Db: db, Config: config, cache: cache}, nil
}

func (a *Api) Routes(prefix string) *gin.Engine {
	router := gin.Default()
	v1 := router.Group(prefix)

	// check api key exist and not expired
	v1.POST("/check", a.Check)

	// check api key and validate body signature
	// only for POST, PUT, PATCH
	v1.POST("/verify", a.Verify)

	manage := v1.Group("/apikeys")
	// create new api key
	manage.POST("", a.CreateApiKey)
	// list all api keys filtering by sub, exp and alg
	manage.POST("/search", a.ListApiKeys)
	// get api key by id
	manage.GET("/:apikey", a.GetApiKey)

	// health and metrics
	health := v1.Group("/health")
	health.GET("/alive", a.HealthLiveness)
	health.GET("/ready", a.HealthReadiness)
	health.GET("/metrics", a.HealthMetrics)

	return router
}
