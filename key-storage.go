package jwtek

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/nitsugaro/go-jwte-manager/v2/jwk"
	"github.com/nitsugaro/go-nstore"
	"github.com/nitsugaro/go-utils/v2/encoding"
)

type Key struct {
	*nstore.Metadata

	Kty          KTY    `json:"kty"`
	Iat          int64  `json:"iat"`
	Exp          int64  `json:"exp"`
	Active       bool   `json:"active"`
	Value        string `json:"value"`
	Use          USE    `json:"use"`
	Alg          ALG    `json:"alg"`
	Purpose      string `json:"purpose"`
	currentValue interface{}
	publicJwk    interface{}
}

func (k *Key) GetValue() interface{} {
	return k.currentValue
}

func (k *Key) IsRsa() bool {
	return k.Kty == "RSA"
}

func (k *Key) IsEc() bool {
	return k.Kty == EC
}

func (k *Key) IsEd() bool {
	return k.Kty == "OKP"
}

func (k *Key) IsHmac() bool {
	return k.Kty == "HMAC"
}

func (k *Key) init() error {
	bytes, err := encoding.DecodeBase64(k.Value)
	if err != nil {
		return err
	}

	if k.IsRsa() {
		key, err := x509.ParsePKCS1PrivateKey(bytes)
		if err != nil {
			return err
		}
		k.currentValue = key

	} else if k.IsEc() {
		key, err := x509.ParseECPrivateKey(bytes)
		if err != nil {
			return err
		}
		k.currentValue = key

	} else if k.IsEd() {
		keyIfc, err := x509.ParsePKCS8PrivateKey(bytes)
		if err != nil {
			return err
		}
		k.currentValue = keyIfc

	} else {
		k.currentValue = bytes
	}

	return nil
}

func NewHMACKey(alg HMAC_ALG, purpose string) *Key {
	key := &Key{
		Active:  true,
		Iat:     time.Now().Unix(),
		Alg:     ALG(alg),
		Use:     SIG,
		Kty:     HMAC,
		Purpose: purpose,
	}

	if alg == HS256 {
		key.Value = encoding.EncodeBase64(mustGetRandomBytes(32))
	} else {
		key.Value = encoding.EncodeBase64(mustGetRandomBytes(64))
	}

	key.init()

	return key
}

func NewRSAKey(alg RSA_ALG, use USE, bits int, purpose string) *Key {
	key := &Key{
		Active:  true,
		Iat:     time.Now().Unix(),
		Alg:     ALG(alg),
		Use:     use,
		Kty:     RSA,
		Purpose: purpose,
	}

	key.Value = encoding.EncodeBase64(x509.MarshalPKCS1PrivateKey(mustGenRSAPrivateKey(bits)))

	key.init()

	return key
}

func NewECKey(alg ES_ALG, use USE, crv elliptic.Curve, purpose string) *Key {
	key := &Key{
		Active:  true,
		Iat:     time.Now().Unix(),
		Alg:     ALG(alg),
		Use:     use,
		Kty:     EC,
		Purpose: purpose,
	}

	bytes, err := x509.MarshalECPrivateKey(mustGenECDSAPrivateKey(crv))
	if err != nil {
		panic(err.Error())
	}

	key.Value = encoding.EncodeBase64(bytes)

	key.init()

	return key
}

func NewEdKey(purpose string) *Key {
	_, priv, err := jwk.GenEd25519Key()
	if err != nil {
		panic(err.Error())
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}

	key := &Key{
		Active:  true,
		Iat:     time.Now().Unix(),
		Alg:     "EdDSA",
		Use:     SIG,
		Kty:     "OKP",
		Purpose: purpose,
		Value:   encoding.EncodeBase64(der),
	}

	key.init()

	return key
}

func (k *Key) GetPublicJWK() (interface{}, error) {
	if k.publicJwk != nil {
		return k.publicJwk, nil
	}

	var publicJwk interface{}
	switch key := k.currentValue.(type) {
	case *rsa.PrivateKey:
		pub := key.Public().(*rsa.PublicKey)
		publicJwk = &jwk.RsaPublicKeyJwk{
			BasicKeyJwk: jwk.BasicKeyJwk{
				Kty: string(RSA),
				Kid: k.ID,
				Use: string(k.Use),
			},
			N: encoding.EncodeBase64URL(pub.N.Bytes()),
			E: encoding.EncodeBase64URL(big.NewInt(int64(pub.E)).Bytes()),
		}

	case *ecdsa.PrivateKey:
		pub := &key.PublicKey
		publicJwk = &jwk.EcPublicKeyJwk{
			BasicKeyJwk: jwk.BasicKeyJwk{
				Kty: string(EC),
				Kid: k.ID,
				Use: string(k.Use),
			},
			Crv: jwk.CurveName(pub.Curve),
			X:   encoding.EncodeBase64URL(pub.X.Bytes()),
			Y:   encoding.EncodeBase64URL(pub.Y.Bytes()),
		}

	case ed25519.PrivateKey:
		pub := key.Public().(ed25519.PublicKey)
		publicJwk = &jwk.EdPublicKeyJwk{
			BasicKeyJwk: jwk.BasicKeyJwk{
				Kty: "OKP",
				Kid: k.ID,
				Use: string(k.Use),
			},
			Crv: "Ed25519",
			X:   encoding.EncodeBase64URL(pub),
		}

	default:
		return nil, jwk.ErrInvalidJwk
	}

	k.publicJwk = publicJwk

	return publicJwk, nil
}
