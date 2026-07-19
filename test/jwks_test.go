package test

import (
	"crypto/elliptic"
	"testing"

	"github.com/nitsugaro/go-jwte-manager/v2/jwk"
)

func TestJwkKeys(t *testing.T) {
	//RSA
	rsaPrivateKey, err := jwk.GenRSAPrivateKey(2048)
	if err != nil {
		t.Errorf("error trying to generate ecdsa key p256: %s", err.Error())
	}

	rsaJwk := jwk.RsaPrivateKeyToJwk(rsaPrivateKey)
	rsaPublicJwk := jwk.RsaPublicKeyToJwk(&rsaPrivateKey.PublicKey)
	if jwk.ToJsonString(rsaJwk) == "{}" {
		t.Error("invalid jwk private key rsa")
	}

	if _, err := jwk.RsaJwkToPrivateKey(rsaJwk); err != nil {
		t.Errorf("error when trying to parse jwk private key: %s", err.Error())
	}

	if _, err := jwk.RsaJwkToPublicKey(rsaPublicJwk); err != nil {
		t.Errorf("error when trying to parse jwk public key: %s", err.Error())
	}

	//EC
	ecPrivateKey, err := jwk.GenECDSAPrivateKey(elliptic.P256())
	if err != nil {
		t.Errorf("error trying to generate ecdsa key p256: %s", err.Error())
	}

	ecJwk := jwk.EcPrivateKeyToJwk(ecPrivateKey)
	ecPublicJwk := jwk.EcPublicKeyToJwk(&ecPrivateKey.PublicKey)
	if jwk.ToJsonString(ecJwk) == "{}" {
		t.Error("invalid jwk private key ecdsa")
	}

	if _, err := jwk.EcJwkToPrivateKey(ecJwk); err != nil {
		t.Errorf("error when trying to parse jwk private key: %s", err.Error())
	}

	if _, err := jwk.EcJwkToPublicKey(ecPublicJwk); err != nil {
		t.Errorf("error when trying to parse jwk public key: %s", err.Error())
	}

	//ED
	edPublicKey, edPrivateKey, err := jwk.GenEd25519Key()
	if err != nil {
		t.Errorf("error trying to generate ecdsa key p256: %s", err.Error())
	}

	edJwk := jwk.EdPrivateKeyToJwk(edPrivateKey)
	edPublicJwk := jwk.EdPublicKeyToJwk(edPublicKey)

	if jwk.ToJsonString(edJwk) == "{}" {
		t.Error("invalid jwk private key ed25519")
	}

	if _, err := jwk.EdJwkToPrivateKey(edJwk); err != nil {
		t.Errorf("error when trying to parse jwk private key: %s", err.Error())
	}

	if _, err := jwk.EdJwkToPublicKey(edPublicJwk); err != nil {
		t.Errorf("error when trying to parse jwk public key: %s", err.Error())
	}
}
