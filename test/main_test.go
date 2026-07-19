package test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwt"
	goconf "github.com/nitsugaro/go-conf"
	jwtek "github.com/nitsugaro/go-jwte-manager/v2"
)

func TestSigningAndEncryption(t *testing.T) {
	goconf.LoadConfig()

	keyStorage := jwtek.GetKeyStorage()
	if keyStorage == nil {
		t.Fatal("key storage was not initialized")
	}

	ecKey := jwtek.NewECKey(jwtek.ES256, jwtek.SIG, elliptic.P256(), jwtek.OIDC_PURPOSE)
	rsaKey := jwtek.NewRSAKey(jwtek.RS256, jwtek.ENC, 2048, jwtek.CIPHER_PURPOSE)
	for _, key := range []*jwtek.Key{ecKey, rsaKey} {
		if err := keyStorage.Save(key); err != nil {
			t.Fatalf("save key: %v", err)
		}
		keyID := key.ID
		t.Cleanup(func() {
			if err := keyStorage.Delete(keyID); err != nil {
				t.Errorf("delete test key %q: %v", keyID, err)
			}
		})
	}

	loadedECKey, err := keyStorage.Load(ecKey.ID)
	if err != nil {
		t.Fatalf("load EC key: %v", err)
	}
	loadedRSAKey, err := keyStorage.Load(rsaKey.ID)
	if err != nil {
		t.Fatalf("load RSA key: %v", err)
	}

	ecPrivateKey, ok := loadedECKey.GetValue().(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("EC key has unexpected type %T", loadedECKey.GetValue())
	}
	rsaPrivateKey, ok := loadedRSAKey.GetValue().(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("RSA key has unexpected type %T", loadedRSAKey.GetValue())
	}

	token, err := jwt.NewBuilder().
		Issuer("yo").
		Subject("usuario123").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1 * time.Minute)).
		Build()
	if err != nil {
		t.Fatalf("build JWT: %v", err)
	}

	signedJWT, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, ecPrivateKey))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}

	header := jwe.NewHeaders()
	if err := header.Set("iat", time.Now().Unix()); err != nil {
		t.Fatalf("set issued-at header: %v", err)
	}
	if err := header.Set("exp", time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatalf("set expiration header: %v", err)
	}

	encrypted, err := jwe.Encrypt(signedJWT,
		jwe.WithKey(jwa.RSA_OAEP_256, &rsaPrivateKey.PublicKey),
		jwe.WithContentEncryption(jwa.A256GCM),
		jwe.WithProtectedHeaders(header),
	)
	if err != nil {
		t.Fatalf("encrypt JWT: %v", err)
	}

	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP_256, rsaPrivateKey))
	if err != nil {
		t.Fatalf("decrypt JWT: %v", err)
	}
	if !bytes.Equal(decrypted, signedJWT) {
		t.Fatal("decrypted JWT does not match the signed JWT")
	}

	parsedToken, err := jwt.Parse(decrypted, jwt.WithKey(jwa.ES256, &ecPrivateKey.PublicKey), jwt.WithValidate(true))
	if err != nil {
		t.Fatalf("parse JWT: %v", err)
	}

	if got := parsedToken.Subject(); got != "usuario123" {
		t.Errorf("subject = %q, want %q", got, "usuario123")
	}
	if got := parsedToken.Issuer(); got != "yo" {
		t.Errorf("issuer = %q, want %q", got, "yo")
	}
}
