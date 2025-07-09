package jwk

import "encoding/json"

type BasicKeyJwk struct {
	Kty string   `json:"kty,omitempty"`
	Kid string   `json:"kid,omitempty"`
	Use string   `json:"use,omitempty"`
	X5t []string `json:"x5t,omitempty"`
	X5c []string `json:"x5c,omitempty"`
}

func ToJsonString[T any](t T) string {
	bytes, err := json.Marshal(t)
	if err != nil {
		return "{}"
	}

	return string(bytes)
}

type RsaPublicKeyJwk struct {
	BasicKeyJwk
	N string `json:"n"`
	E string `json:"e"`
}

type RsaPrivateKeyJwk struct {
	RsaPublicKeyJwk
	D string `json:"d"`
	P string `json:"p,omitempty"`
	Q string `json:"q,omitempty"`
}

type EcPublicKeyJwk struct {
	BasicKeyJwk
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type EcPrivateKeyJwk struct {
	EcPublicKeyJwk
	D string `json:"d"`
}

type EdPublicKeyJwk struct {
	BasicKeyJwk
	Crv string `json:"crv"`
	X   string `json:"x"`
}

type EdPrivateKeyJwk struct {
	EdPublicKeyJwk
	D string `json:"d"`
}
