package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/nitsugaro/go-utils/v2/encoding"
)

func CurveName(c elliptic.Curve) string {
	switch c {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return ""
	}
}

func GenECDSAPrivateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func EcJwkToPrivateKey(jwk *EcPrivateKeyJwk) (*ecdsa.PrivateKey, error) {
	if jwk.Kty != "EC" {
		return nil, ErrInvalidJwk
	}
	curve := map[string]elliptic.Curve{
		"P-256": elliptic.P256(),
		"P-384": elliptic.P384(),
		"P-521": elliptic.P521(),
	}[jwk.Crv]
	if curve == nil {
		return nil, ErrUnsopportedCurve
	}

	xBytes, _ := encoding.DecodeBase64URL(jwk.X)
	yBytes, _ := encoding.DecodeBase64URL(jwk.Y)
	dBytes, _ := encoding.DecodeBase64URL(jwk.D)

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		},
		D: new(big.Int).SetBytes(dBytes),
	}, nil
}

func EcJwkToPublicKey(jwk *EcPublicKeyJwk) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" {
		return nil, ErrInvalidJwk
	}

	curve := map[string]elliptic.Curve{
		"P-256": elliptic.P256(),
		"P-384": elliptic.P384(),
		"P-521": elliptic.P521(),
	}[jwk.Crv]
	if curve == nil {
		return nil, ErrUnsopportedCurve
	}

	xBytes, err := encoding.DecodeBase64URL(jwk.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := encoding.DecodeBase64URL(jwk.Y)
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func EcPrivateKeyToJwk(priv *ecdsa.PrivateKey) *EcPrivateKeyJwk {
	return &EcPrivateKeyJwk{
		EcPublicKeyJwk: EcPublicKeyJwk{
			BasicKeyJwk: BasicKeyJwk{
				Kty: "EC",
			},
			Crv: CurveName(priv.Curve),
			X:   encoding.EncodeBase64URL(priv.PublicKey.X.Bytes()),
			Y:   encoding.EncodeBase64URL(priv.PublicKey.Y.Bytes()),
		},
		D: encoding.EncodeBase64URL(priv.D.Bytes()),
	}
}

func EcPublicKeyToJwk(pub *ecdsa.PublicKey) *EcPublicKeyJwk {
	return &EcPublicKeyJwk{
		BasicKeyJwk: BasicKeyJwk{
			Kty: "EC",
		},
		Crv: CurveName(pub.Curve),
		X:   encoding.EncodeBase64URL(pub.X.Bytes()),
		Y:   encoding.EncodeBase64URL(pub.Y.Bytes()),
	}
}
