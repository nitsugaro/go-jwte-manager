package jwtek

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"

	"github.com/nitsugaro/go-jwte-manager/v2/jwk"
	"github.com/nitsugaro/go-utils/v2/crypto"
)

func mustGetRandomBytes(length int) []byte {
	bytes, err := crypto.GetRandBytes(length)
	if err != nil {
		panic(err.Error())
	}

	return bytes
}

func mustGenRSAPrivateKey(bits int) *rsa.PrivateKey {
	rkey, err := jwk.GenRSAPrivateKey(bits)
	if err != nil {
		panic(err.Error())
	}

	return rkey
}

func mustGenECDSAPrivateKey(crv elliptic.Curve) *ecdsa.PrivateKey {
	eckey, err := jwk.GenECDSAPrivateKey(crv)
	if err != nil {
		panic(err.Error())
	}

	return eckey
}

func initKeys() {
	//HMAC
	keyStorage.Save(NewHMACKey(HS256, OIDC_PURPOSE))
	keyStorage.Save(NewHMACKey(HS384, OIDC_PURPOSE))
	keyStorage.Save(NewHMACKey(HS512, OIDC_PURPOSE))

	//RSA
	keyStorage.Save(NewRSAKey(RS256, SIG, 2048, OIDC_PURPOSE))
	keyStorage.Save(NewRSAKey(RS256, ENC, 2048, OIDC_PURPOSE))

	keyStorage.Save(NewRSAKey(RS384, SIG, 4096, OIDC_PURPOSE))
	keyStorage.Save(NewRSAKey(RS384, ENC, 4096, OIDC_PURPOSE))

	keyStorage.Save(NewRSAKey(RS512, SIG, 4096, OIDC_PURPOSE))
	keyStorage.Save(NewRSAKey(RS512, ENC, 4096, OIDC_PURPOSE))

	//EC
	keyStorage.Save(NewECKey(ES256, SIG, elliptic.P256(), OIDC_PURPOSE))
	keyStorage.Save(NewECKey(ES256, ENC, elliptic.P256(), OIDC_PURPOSE))

	keyStorage.Save(NewECKey(ES384, SIG, elliptic.P384(), OIDC_PURPOSE))
	keyStorage.Save(NewECKey(ES384, ENC, elliptic.P384(), OIDC_PURPOSE))

	keyStorage.Save(NewECKey(ES512, SIG, elliptic.P521(), OIDC_PURPOSE))
	keyStorage.Save(NewECKey(ES512, ENC, elliptic.P521(), OIDC_PURPOSE))

	//ED
	keyStorage.Save(NewEdKey(OIDC_PURPOSE))
}
