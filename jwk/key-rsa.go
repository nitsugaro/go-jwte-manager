package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"math/big"

	"github.com/nitsugaro/go-utils/encoding"
)

func GenRSAPrivateKey(bits int) (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, bits)
}

func RsaJwkToPrivateKey(jwk *RsaPrivateKeyJwk) (*rsa.PrivateKey, error) {
	if jwk.Kty != "RSA" {
		return nil, ErrInvalidJwk
	}

	nBytes, _ := encoding.DecodeBase64URL(jwk.N)
	eBytes, _ := encoding.DecodeBase64URL(jwk.E)
	dBytes, _ := encoding.DecodeBase64URL(jwk.D)

	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: e,
		},
		D: new(big.Int).SetBytes(dBytes),
	}

	if jwk.P != "" && jwk.Q != "" {
		pBytes, _ := encoding.DecodeBase64URL(jwk.P)
		qBytes, _ := encoding.DecodeBase64URL(jwk.Q)

		priv.Primes = []*big.Int{
			new(big.Int).SetBytes(pBytes),
			new(big.Int).SetBytes(qBytes),
		}

		priv.Precompute()
	}

	return priv, nil
}

func RsaJwkToPublicKey(jwk *RsaPublicKeyJwk) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, ErrInvalidJwk
	}

	nb, err := encoding.DecodeBase64URL(jwk.N)
	if err != nil {
		return nil, err
	}
	eb, err := encoding.DecodeBase64URL(jwk.E)
	if err != nil {
		return nil, err
	}

	e := 0
	for _, b := range eb {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nb),
		E: e,
	}, nil
}

func RsaPublicKeyToJwk(pub *rsa.PublicKey) *RsaPublicKeyJwk {
	return &RsaPublicKeyJwk{
		BasicKeyJwk: BasicKeyJwk{
			Kty: "RSA",
		},
		N: encoding.EncodeBase64URL(pub.N.Bytes()),
		E: encoding.EncodeBase64URL(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func RsaPrivateKeyToJwk(priv *rsa.PrivateKey) *RsaPrivateKeyJwk {
	jwk := &RsaPrivateKeyJwk{
		RsaPublicKeyJwk: *RsaPublicKeyToJwk(&priv.PublicKey),
		D:               encoding.EncodeBase64URL(priv.D.Bytes()),
	}

	if len(priv.Primes) >= 2 {
		jwk.P = encoding.EncodeBase64URL(priv.Primes[0].Bytes())
		jwk.Q = encoding.EncodeBase64URL(priv.Primes[1].Bytes())
	}

	return jwk
}
