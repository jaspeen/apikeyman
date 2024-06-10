<p align="left">
    <a href="https://github.com/jaspeen/apikeyman/actions/workflows/ci.yml"><img src="https://github.com/jaspeen/apikeyman/actions/workflows/ci.yml/badge.svg" alt="Build Status"></a>
    <a href="https://goreportcard.com/report/github.com/jaspeen/apikeyman"><img src="https://goreportcard.com/badge/github.com/jaspeen/apikeyman" alt="Go Report Card"></a>
    <a href="https://pkg.go.dev/github.com/jaspeen/apikeyman"><img src="https://pkg.go.dev/badge/www.github.com/jaspeen/apikeyman" alt="PkgGoDev"></a>
</p>

Simple authentication service to store and validate API keys.
Intended to be used with ORY oathkeeper or similar proxies to authenticate request using API keys.

## Features
- Store API keys in sql database. Available databases are: `postgres`
- Generate API keys
- Check API keys with care
- Generate and validate signatures for requests using assymetric encryption. See below 

## Signature algorithms
Names are taken from [this list](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms)
| Algorithm | Description                          |
| ---    | ---                                     |
| RS256  | RSASSA-PKCS1-v1_5 using SHA-256	       |
| RS512  | RSASSA-PKCS1-v1_5 using SHA-512	       |
| ES256  | ECDSA using P-256 and SHA-256		       |
| ES256K | ECDSA using secp256k1 and SHA-256       |
| EdDSA  | Ed25519                                 |

Public keys encoded as PKIX and private as PKCS8 asn1 binary. String encoding depends on usage - 
for REST API it is base64 encoded(same as middle part of PEM file), comman line uses PEM files.

## Installation

### Local
Download binary release from [releases](https://github.com/jaspeen/apikeyman/releases) page.
Start the service with the following command:
```bash
./apikeyman server --db postgres://user:password@localhost:5432/dbname
```
See [Configuration](#Configuration) for more details.

### Docker compose
```bash
cd deploy/compose
docker-compose up
```

### Helm chart
Repo: https://jaspeen.github.io/apikeyman
```bash
helm show all apikeyman --repo https://jaspeen.github.io/apikeyman
```

## Usage
### Command line
There are commands to generate, sign and verify signatures. 
See helm in `apikeyman -h` and example usages in [cmd/apikeyman/tests/openssl-compat-tests.sh](cmd/apikeyman/tests/openssl-compat-tests.sh)
### Service
#### Create API Key
```bash
$ curl http://localhost:8080/apikeys -d '{"sub": "users:ci", "alg": "ES256", "name": "gh_action_token", "exp_sec": 86400, "extra": {"arbitrary": "data"}}' -H 'Content-Type: application/json'
```
```json
{
  "apikey":"1:HFqAdqST5gdRrV8KT7YqCm2Hcby4C7Y7znD5CTAWiMLc",
  "publickey":"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEt6RHimLFlLD8Q0ts+yNCdK39PxE4We9BAdFkhY6cX9RosnBYwD07GN88V1OySgUUOa3hYzehpFZrwJpmm4R6CA==",
  "privatekey":"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgtp3DF6oKRBDKSFrtbkJNtlwxIhDNkJD7wYHMD0OVRqqhRANCAAS3pEeKYsWUsPxDS2z7I0J0rf0/EThZ70EB0WSFjpxf1GiycFjAPTsY3zxXU7JKBRQ5reFjN6GkVmvAmmabhHoI"
}
```

#### Check API Key
```bash
curl -X POST http://localhost:8080/check  -H 'X-API-KEY: 1:HFqAdqST5gdRrV8KT7YqCm2Hcby4C7Y7znD5CTAWiMLc' -d 'anybody'
```
```json
{
  "sub": "users:ci"
}
```

#### Verify signature
```bash
curl -X POST http://localhost:8080/verify -H 'X-API-KEY: 1:HFqAdqST5gdRrV8KT7YqCm2Hcby4C7Y7znD5CTAWiMLc' -H "X-Timestamp: "$(date +%s) -H 'X-Signature: XXX' -d 'anybody'
```
```json
{
  "sub": "users:ci"
}
```

### Get key
```bash
curl http://localhost:8080/apikeys/1:HFqAdqST5gdRrV8KT7YqCm2Hcby4C7Y7znD5CTAWiMLc
```
```json
{
  "sub": "users:ci",
  "alg": "ES256",
  "name": "gh_action_token",
  "exp_sec": 86400,
  "extra": {
    "arbitrary": "data"
    }
}
```

### Search keys by subject
```bash
curl http://localhost:8080/apikeys?sub=users:ci
```
```json
[
  {
    "sub": "users:ci",
    "alg": "ES256",
    "name": "gh_action_token",
    "exp_sec": 86400,
    "extra": {
      "arbitrary": "data"
    }
  }
]
```

## License
[MIT](https://choosealicense.com/licenses/mit/)

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
