package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/jaspeen/apikeyman/algo"
	_ "github.com/jaspeen/apikeyman/algo/all"
	"github.com/jaspeen/apikeyman/api"
	"github.com/jaspeen/apikeyman/db/migrations"
	_ "github.com/lib/pq"
	"github.com/urfave/cli/v2"
)

func SlogLevelFromString(lvl string) (programLevel slog.Level) {
	switch strings.ToUpper(lvl) {
	case "DEBUG":
		programLevel = slog.LevelDebug
	case "INFO":
		programLevel = slog.LevelInfo
	case "WARN":
		programLevel = slog.LevelWarn
	case "ERROR":
		programLevel = slog.LevelError
	default:
		log.Fatalf("Invalid log level %s", lvl)
	}
	return programLevel
}

func InitLogger(lvlStr string) {
	var lvl = SlogLevelFromString(lvlStr)
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(h))
}

func Retry(maxWait time.Duration, op func() error) error {
	if maxWait == 0 {
		maxWait = time.Minute
	}
	bo := backoff.NewExponentialBackOff()
	bo.MaxInterval = time.Second * 5
	bo.MaxElapsedTime = maxWait
	if err := backoff.Retry(op, bo); err != nil {
		if bo.NextBackOff() == backoff.Stop {
			return fmt.Errorf("reached retry deadline: %w", err)
		}
		return err
	}

	return nil
}

func main() {
	signAlgoNames := "[" + strings.Join(algo.GetSignAlgorithmNames(), ",") + "]"
	app := &cli.App{
		Name:            "apikeyman",
		Usage:           "Service to generate, store and validate API keys",
		HideHelpCommand: true,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "log",
				Value: "INFO",
				Usage: "Log level",
			},
		},
		Before: func(cCtx *cli.Context) error {
			InitLogger(cCtx.String("log"))
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:  "server",
				Usage: "Starts server",
				Flags: []cli.Flag{
					&cli.DurationFlag{
						Name:  "timestamp-threshold-ms",
						Usage: "If differs more than specifieid ms from now timestamp is considered invalid",
						Value: 15000,
					},
					&cli.StringFlag{
						Name:     "db",
						Aliases:  []string{"d"},
						EnvVars:  []string{"DSN"},
						Required: true,
						Value:    "postgresql://postgres:postgres@localhost:5432/apikeyman",
						Usage:    "Database connection string",
					},
					&cli.StringFlag{
						Name:    "addr",
						Aliases: []string{"a"},
						Value:   "0.0.0.0:8080",
						Usage:   "Address to listen on",
					},
					&cli.StringFlag{
						Name:    "base-path",
						Aliases: []string{"p"},
						Value:   "/",
						Usage:   "Base URL path for API",
					},
					&cli.Uint64Flag{
						Name:  "cache-max-size",
						Value: 0,
						Usage: "Max number of keys to cache",
					},
					&cli.DurationFlag{
						Name:  "cache-ttl",
						Value: 5 * time.Minute,
						Usage: "Time to live for cache entries",
					},
				},
				Action: func(cCtx *cli.Context) error {
					db, err := sql.Open("postgres", cCtx.String("db"))
					if err != nil {
						panic(err)
					}
					defer db.Close()

					err = Retry(30*time.Second, func() error {
						err := db.Ping()
						if err != nil {
							slog.Error("Failed to connect to database", "error", err)
						}
						return err
					})

					if err != nil {
						panic(err)
					}

					a, err := api.NewApi(
						slog.Default(),
						db,
						api.Config{
							ApiKeyHeaderName:     api.API_KEY_DEFAULT_HEADER,
							ApiKeyQueryParamName: "apikey",
							SignatureHeaderName:  api.SIGNATURE_DEFAULT_HEADER,
							SignatureQueryParam:  "signature",
							TimestampHeaderName:  api.TIMESTAMP_DEFAULT_HEADER,
							TimestampQueryParam:  "timestamp",
							TimestampExpiration:  cCtx.Duration("timestamp-threshold-ms"),
							DefaultKeyExpiration: 30 * 24 * time.Hour,
							CacheMaxSize:         cCtx.Uint64("cache-max-size"),
							CacheTTL:             cCtx.Duration("cache-ttl"),
						})
					if err != nil {
						panic(err)
					}
					r := a.Routes(cCtx.String("base-path"))
					return r.Run(cCtx.String("addr"))
				},
			},
			{
				Name:  "migrate",
				Usage: "Initializes or update the database schema",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:    "db",
						Aliases: []string{"d"},
						EnvVars: []string{"DSN"},
						Value:   "postgresql://postgres:postgres@localhost:5432/apikeyman",
						Usage:   "Database connection string",
					},
				},
				Action: func(cCtx *cli.Context) error {
					db, err := sql.Open("postgres", cCtx.String("db"))
					if err != nil {
						panic(err)
					}
					defer db.Close()
					return migrations.MigrateDb(db)
				},
			},
			{
				Name:  "gen",
				Usage: "Generate keypair",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "alg",
						Required: true,
						Aliases:  []string{"a"},
						Usage:    "Algorithm. Available algorithms: " + signAlgoNames,
					},
					&cli.PathFlag{
						Name:  "private",
						Usage: "Private key file",
					},
					&cli.PathFlag{
						Name:  "public",
						Usage: "Public key file",
					},
				},
				Action: func(cCtx *cli.Context) error {
					algName := cCtx.String("alg")
					alg := algo.GetSignAlgorithm(algName)
					if alg == nil {
						return cli.Exit("Unknown algorithm: "+algName, 1)
					}
					keys, err := alg.Generate()
					if err != nil {
						return cli.Exit(err, 1)
					}

					var privOut io.Writer = os.Stdout
					if cCtx.IsSet("private") {
						privFile, err := os.Create(cCtx.String("private"))
						if err != nil {
							return cli.Exit(err, 1)
						}
						defer privFile.Close()
						privOut = privFile
					}

					var pubOut io.Writer = os.Stdout
					if cCtx.IsSet("public") {
						pubFile, err := os.Create(cCtx.String("public"))
						if err != nil {
							return cli.Exit(err, 1)
						}
						defer pubFile.Close()
						pubOut = pubFile
					}

					algo.PublicKeyToPem(keys.Public, pubOut)
					algo.PrivateKeyToPem(keys.Private, privOut)

					return nil
				},
			},
			{
				Name:  "sign",
				Usage: "Generate signature",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "alg",
						Required: true,
						Aliases:  []string{"a"},
						Usage:    "Algorithm. Available algorithms: " + signAlgoNames,
					},
					&cli.PathFlag{
						Name:     "private",
						Required: true,
						Usage:    "Private key file",
					},
					&cli.PathFlag{
						Name:    "signature",
						Aliases: []string{"s"},
						Usage:   "Signature file. Omit to write to stdout",
					},
					&cli.PathFlag{
						Name:  "data",
						Usage: "Data file. Omit to read from stdin",
					},
				},
				Action: func(cCtx *cli.Context) error {
					algoName := cCtx.String("alg")
					alg := algo.GetSignAlgorithm(algoName)
					if alg == nil {
						return cli.Exit("Unknown algorithm: "+algoName, 1)
					}
					privateKeyFile, err := os.Open(cCtx.String("private"))
					if err != nil {
						return cli.Exit(err, 1)
					}
					defer privateKeyFile.Close()
					privateKeyPkcs8, err := io.ReadAll(privateKeyFile)
					if err != nil {
						return cli.Exit(err, 1)
					}
					pemBlock, _ := pem.Decode(privateKeyPkcs8)
					if pemBlock == nil {
						return cli.Exit("Invalid private key", 1)
					}
					privateKey := pemBlock.Bytes

					var dataIn io.Reader = os.Stdin
					if cCtx.IsSet("data") {
						dataFile, err := os.Open(cCtx.String("data"))
						if err != nil {
							return cli.Exit(err, 1)
						}
						defer dataFile.Close()
						dataIn = dataFile
					}

					dataBytes, err := io.ReadAll(dataIn)
					if err != nil {
						return cli.Exit(err, 1)
					}

					signature, err := alg.Sign(privateKey, dataBytes)
					if err != nil {
						return cli.Exit(err, 1)
					}

					var signatureOut io.Writer = os.Stdout
					if cCtx.IsSet("signature") {
						signatureFile, err := os.Create(cCtx.String("signature"))
						if err != nil {
							return cli.Exit(err, 1)
						}
						defer signatureFile.Close()
						signatureOut = signatureFile
					}

					signatureOut.Write([]byte(base64.StdEncoding.EncodeToString(signature)))
					return nil
				},
			},
			{
				Name:  "verify",
				Usage: "Verify signature",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "alg",
						Required: true,
						Aliases:  []string{"a"},
						Usage:    "Algorithm. Available algorithms: " + signAlgoNames,
					},
					&cli.PathFlag{
						Name:     "public",
						Required: true,
						Usage:    "Public key file",
					},
					&cli.PathFlag{
						Name:  "data",
						Usage: "Data file. Omit to read from stdin",
					},
					&cli.StringFlag{
						Name:     "signature",
						Aliases:  []string{"s"},
						Required: true,
						Usage:    "Signature",
					},
				},
				Action: func(cCtx *cli.Context) error {
					algoName := cCtx.String("alg")
					alg := algo.GetSignAlgorithm(algoName)
					if alg == nil {
						return cli.Exit("Unknown algorithm: "+algoName, 1)
					}

					publicKeyFile, err := os.Open(cCtx.String("public"))
					if err != nil {
						return cli.Exit(err, 1)
					}
					defer publicKeyFile.Close()
					publicKeyPkix, err := io.ReadAll(publicKeyFile)
					if err != nil {
						return cli.Exit(err, 1)
					}
					pemBlock, _ := pem.Decode(publicKeyPkix)
					if pemBlock == nil {
						return cli.Exit("Invalid public key", 1)
					}
					publicKey := pemBlock.Bytes

					var dataIn io.Reader = os.Stdin
					if cCtx.IsSet("data") {
						dataFile, err := os.Open(cCtx.String("data"))
						if err != nil {
							return cli.Exit(err, 1)
						}
						defer dataFile.Close()
						dataIn = dataFile
					}

					dataBytes, err := io.ReadAll(dataIn)
					if err != nil {
						return cli.Exit(err, 1)
					}

					signature, err := base64.StdEncoding.DecodeString(cCtx.String("signature"))
					if err != nil {
						return cli.Exit(err, 1)
					}

					err = alg.ValidateSignature(publicKey, signature, dataBytes)
					if err != nil {
						return cli.Exit(err, 1)
					}
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		panic(err)
	}
}
