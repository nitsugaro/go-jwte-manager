package jwtek

type USE string

const (
	SIG  USE = "sig"
	ENC  USE = "enc"
	NONE USE = "none"
)

type KTY string

const (
	RSA  KTY = "RSA"
	EC   KTY = "EC"
	HMAC KTY = "HMAC"
)

type ALG string

type HMAC_ALG ALG

const (
	HS256 HMAC_ALG = "HS256"
	HS384 HMAC_ALG = "HS384"
	HS512 HMAC_ALG = "HS512"
)

type RSA_ALG ALG

const (
	RS256 RSA_ALG = "RS256"
	RS384 RSA_ALG = "RS384"
	RS512 RSA_ALG = "RS512"
)

type ES_ALG ALG

const (
	ES256 ES_ALG = "ES256"
	ES384 ES_ALG = "ES384"
	ES512 ES_ALG = "ES512"
)

/* PURPOSES */

const (
	INTERNAL_PURPOSE = "INTERNAL"
	CIPHER_PURPOSE   = "CIPHER"
	OIDC_PURPOSE     = "OIDC"
)
