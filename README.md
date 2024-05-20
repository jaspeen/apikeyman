Simple authentication service to store and validate API keys.
Intended to be used with ORY oathkeeper or similar proxies to authenticate request using API keys.

## Features
- Store API keys in sql database. Available dbs are `postgres`, `sqlite`
- Generate API keys
- Check API keys with care for timing attack
- Generate and validate signatures for requests using assymetric encryption. Available algorithms see below

## Signature algorithms
Names are taken from [this list](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms)
| Algorithm | Description                          |
| ---    | ---                                     |
| RS256  | RSASSA-PKCS1-v1_5 using SHA-256	       |
| RS512  | RSASSA-PKCS1-v1_5 using SHA-512	       |
| ES256  | ECDSA using P-256 and SHA-256		       |
| ES256K | ECDSA using secp256k1 and SHA-256       |
| EdDSA  | Ed25519                                 |

Public and private keys are PEM-encoded.

## Installation

### Local
Download binary release from [releases](https://github.com/jaspeen/apikeyman/releases) page.
Start the service with the following command:
```bash
./apikeyman --config config.yaml
```
See [Configuration](#Configuration) for more details.

### Docker
```bash
docker run -v /path/to/config.yaml:/config.yaml -p 8080:8080 jaspeen/apikeyman
```

## Configuration
```yaml
db: sqlite # database connection string
```

## Usage
### Create API key
```bash
$ curl -X POST http://localhost:8080/apikeys -d '{"name": "ci", "alg": "ES256K"}'
```
```json
{"apikey": "deafbeef", "pkey": "xxx"}
```

### Validate API key
```bash

curl -X POST http://localhost:8080/apikeys/validate -d '{"
  "key": "
  "signature": ""
}'
```

## License
[MIT](https://choosealicense.com/licenses/mit/)

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
