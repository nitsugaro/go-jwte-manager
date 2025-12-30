# jwtek

jwtek is a Go package for managing, storing, and using cryptographic keys (JWKs) aimed at JWT signing, verification, and related operations. It provides:

- Local key storage (KeyStorage) with loading, saving, and automatic generation of default keys.
- Support for external JWK sets fetched dynamically from remote URLs with configurable caching (`ExternalJwkStorage`).
- Handling of RSA, EC (P-256, P-384, P-521), Ed25519, and HMAC private keys.
- Extraction and generation of public keys in JWK format for OIDC-compatible public endpoints.
- JWT validation utilities that retrieve keys from JWT headers (jwk) or URIs (jku).

## Key Features

```
Supports RSA, ECDSA, Ed25519, and HMAC keys.
Automatic loading from disk and default key generation if none exist.
HTTP-based fetching and caching of external JWKS.
Generation of public JWKs suitable for OIDC discovery endpoints.
Helper functions for base64 serialization and key parsing.
Flexible JWT validation with key lookup from token headers or external sources.
```

### Usage

```go
goconf.LoadConfig() //this will load .config.json by default

keyStorage := jwtek.GetKeyStorage()
keys, total := keyStorage.Query(
	jwtek.ChainCondition(
        jwtek.IsActive,
        jwtek.IsNotExpired,
        jwtek.IsAlg(jwtek.ALG(jwtek.ES256)),
        jwtek.IsPurpose(jwtek.OIDC_PURPOSE),
        jwtek.IsSigUse,
    ),
	2,
)

rsaKey384, _ := keyStorage.Load("ffb09871-5bec-4bc8-ac3d-b941675e2494")
rsaPrivKey := rsaKey384.GetValue().(*rsa.PrivateKey)

ecKey := jwtek.NewECKey(jwtek.ES256, jwtek.SIG, elliptic.P256(), jwtek.OIDC_PURPOSE)
keyStorage.Save(ecKey)

keyStorage.Delete("ffb09871-5bec-4bc8-ac3d-b941675e2494")
```

## Config

```json
{
  "jwtek": {
    "keys": {
      "folder": "custom/keys", //default: jwtek/keys/
      "generate_defaults": false //default: true
    },
    "external_jwks": {
      "folder": "custom/jwks", //default: jwtek/jwks/
      "cache_seconds": 60 //default: 60
    }
  }
}
```
