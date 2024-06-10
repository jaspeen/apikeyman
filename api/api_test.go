package api_test

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jaspeen/apikeyman/algo"
	_ "github.com/jaspeen/apikeyman/algo/all"
	"github.com/jaspeen/apikeyman/api"
	"github.com/jaspeen/apikeyman/db/migrations"
	_ "github.com/lib/pq"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var db *sql.DB

func TestMain(m *testing.M) {
	flag.Parse()

	if testing.Short() {
		os.Exit(m.Run())
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	log.Println("Starting test database")
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not construct pool: %s", err)
	}

	// uses pool to try to connect to Docker
	err = pool.Client.Ping()
	if err != nil {
		log.Fatalf("Could not connect to Docker: %s", err)
	}
	log.Println("Docker connected")

	// pulls an image, creates a container based on it and runs it
	resource, err := pool.Run("postgres", "15", []string{"POSTGRES_PASSWORD=secret"})
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}

	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	if err := pool.Retry(func() error {
		var err error
		db, err = sql.Open("postgres", fmt.Sprintf("postgres://postgres:secret@localhost:%s/postgres?sslmode=disable", resource.GetPort("5432/tcp")))
		if err != nil {
			log.Println("Could not open database connection, retrying...")
			return err
		}
		return db.Ping()
	}); err != nil {
		log.Fatalf("Could not connect to database: %s", err)
	}

	err = migrations.MigrateDb(db)
	if err != nil {
		log.Fatalf("Could not migrate database: %s", err)
	}

	code := m.Run()

	// You can't defer this because os.Exit doesn't care for defer
	if err := pool.Purge(resource); err != nil {
		log.Fatalf("Could not purge resource: %s", err)
	}

	os.Exit(code)
}

func createRouter() *gin.Engine {
	api := api.Api{Db: db, Log: slog.Default(), Config: api.Config{
		ApiKeyHeaderName:     api.API_KEY_DEFAULT_HEADER,
		ApiKeyQueryParamName: "apikey",
		SignatureHeaderName:  api.SIGNATURE_DEFAULT_HEADER,
		SignatureQueryParam:  "signature",
		TimestampHeaderName:  api.TIMESTAMP_DEFAULT_HEADER,
		TimestampQueryParam:  "timestamp",
		TimestampExpiration:  5 * time.Minute,
		DefaultKeyExpiration: 24 * time.Hour,
	}}
	return api.Routes("/")
}

func TestCreateApiKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	router := createRouter()

	// create key
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/apikeys", strings.NewReader(`{"sub": "testsub", "alg": "ES256", "name": "test"}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, 200, w.Code)
	var resp struct {
		ApiKey     string `json:"apikey"`
		PublicKey  string `json:"publickey"`
		PrivateKey string `json:"privatekey"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.Nil(t, err)
	assert.NotEmpty(t, resp.ApiKey)
	assert.NotEmpty(t, resp.PublicKey)
	assert.NotEmpty(t, resp.PrivateKey)

	// check api key
	var checkResp struct {
		Sub string `json:"sub"`
	}
	t.Run("check", func(t *testing.T) {
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("POST", "/check", nil)
		req.Header.Set(api.API_KEY_DEFAULT_HEADER, resp.ApiKey)
		router.ServeHTTP(w, req)

		require.Equal(t, 200, w.Code)
		err = json.Unmarshal(w.Body.Bytes(), &checkResp)
		require.Nil(t, err)
		assert.Equal(t, "testsub", checkResp.Sub)
	})

	// validate api key
	t.Run("validate", func(t *testing.T) {
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("POST", "/verify", strings.NewReader("testdata"))
		req.Header.Set(api.API_KEY_DEFAULT_HEADER, resp.ApiKey)

		privateKeyBytes, err := algo.Base64ToKey(resp.PrivateKey)
		require.Nil(t, err)
		timestampStr := fmt.Sprintf("%d", time.Now().Unix())
		req.Header.Set(api.TIMESTAMP_DEFAULT_HEADER, timestampStr)
		signatureBytes, err := algo.GetSignAlgorithm("ES256").Sign(privateKeyBytes, append([]byte("testdata"), []byte(timestampStr)...))
		require.Nil(t, err)
		req.Header.Set(api.SIGNATURE_DEFAULT_HEADER, base64.StdEncoding.EncodeToString(signatureBytes))

		router.ServeHTTP(w, req)
		require.Equal(t, 200, w.Code)
		assert.Equal(t, "testsub", checkResp.Sub)
	})

	// get api key
	t.Run("get", func(t *testing.T) {
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("GET", "/apikeys/"+resp.ApiKey, nil)

		router.ServeHTTP(w, req)
		require.Equal(t, 200, w.Code)

		var res api.ApiKeyResponse
		bodyBytes := w.Body.Bytes()
		log.Println(string(bodyBytes))
		err = json.Unmarshal(bodyBytes, &res)
		require.Nil(t, err)
		assert.Equal(t, "testsub", res.Sub)
		assert.Equal(t, "test", res.Name)
		assert.Equal(t, "ES256", res.Alg)
		assert.NotEmpty(t, res.Key)
		assert.NotEmpty(t, res.Exp)
		assert.Truef(t, res.Exp.After(time.Now().Add(23*time.Hour)) && res.Exp.Before(time.Now().Add(25*time.Hour)), "exp should be default 24h")
	})

	// list api keys
	t.Run("list", func(t *testing.T) {
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("POST", "/apikeys/search", strings.NewReader(`{"sub": "testsub"}`))
		req.Header.Set("Content-Type", "application/json")

		router.ServeHTTP(w, req)
		require.Equal(t, 200, w.Code)

		var res []api.ApiKeyResponse
		err = json.Unmarshal(w.Body.Bytes(), &res)
		require.Nil(t, err)
		require.Len(t, res, 1)
		require.Equal(t, "testsub", res[0].Sub)
		require.Equal(t, "test", res[0].Name)
	})
}

func TestExpiration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}
	router := createRouter()

	// create key
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/apikeys", strings.NewReader(`{"sub": "testsub", "alg": "ES256", "name": "test", "exp_sec": 1}`))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	require.Equal(t, 200, w.Code)
	var resp struct {
		ApiKey     string `json:"apikey"`
		PublicKey  string `json:"publickey"`
		PrivateKey string `json:"privatekey"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.Nil(t, err)

	// wait for 1s
	time.Sleep(1 * time.Second)

	// check the key is expired and we get unauthorized
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/check", nil)
	req.Header.Set(api.API_KEY_DEFAULT_HEADER, resp.ApiKey)
	router.ServeHTTP(w, req)
	require.Equal(t, 401, w.Code)

	// check that verify also returns unauthorized
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/verify", strings.NewReader("testdata"))
	req.Header.Set(api.API_KEY_DEFAULT_HEADER, resp.ApiKey)

	privateKeyBytes, err := algo.Base64ToKey(resp.PrivateKey)
	require.Nil(t, err)
	timestampStr := fmt.Sprintf("%d", time.Now().Unix())
	req.Header.Set(api.TIMESTAMP_DEFAULT_HEADER, timestampStr)
	signatureBytes, err := algo.GetSignAlgorithm("ES256").Sign(privateKeyBytes, append([]byte("testdata"), []byte(timestampStr)...))
	require.Nil(t, err)
	req.Header.Set(api.SIGNATURE_DEFAULT_HEADER, base64.StdEncoding.EncodeToString(signatureBytes))

	router.ServeHTTP(w, req)
	require.Equal(t, 401, w.Code)
}
