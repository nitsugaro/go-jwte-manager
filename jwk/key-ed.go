package jwk

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/nitsugaro/go-utils/encoding"
)

func GenEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func EdJwkToPrivateKey(jwk *EdPrivateKeyJwk) (*ed25519.PrivateKey, error) {
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, ErrInvalidJwk
	}
	d, err := encoding.DecodeBase64URL(jwk.D)
	x, _ := encoding.DecodeBase64URL(jwk.X)

	// Ed25519 keys are 64 bytes: d (32) + x (32)
	priv := append(d, x...)
	privateKey := ed25519.PrivateKey(priv)
	return &privateKey, err
}

func EdJwkToPublicKey(jwk *EdPublicKeyJwk) (*ed25519.PublicKey, error) {
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, ErrInvalidOkpKey
	}
	x, err := encoding.DecodeBase64URL(jwk.X)
	if err != nil {
		return nil, err
	}

	publicKey := ed25519.PublicKey(x)
	return &publicKey, nil
}

func EdPublicKeyToJwk(pub ed25519.PublicKey) *EdPublicKeyJwk {
	return &EdPublicKeyJwk{
		BasicKeyJwk: BasicKeyJwk{
			Kty: "OKP",
		},
		Crv: "Ed25519",
		X:   encoding.EncodeBase64URL(pub),
	}
}

func EdPrivateKeyToJwk(priv ed25519.PrivateKey) *EdPrivateKeyJwk {
	d := priv[:32]
	x := priv[32:]

	return &EdPrivateKeyJwk{
		EdPublicKeyJwk: EdPublicKeyJwk{
			BasicKeyJwk: BasicKeyJwk{
				Kty: "OKP",
			},
			Crv: "Ed25519",
			X:   encoding.EncodeBase64URL(x),
		},
		D: encoding.EncodeBase64URL(d),
	}
}
