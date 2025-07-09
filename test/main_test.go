package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwt"
	goconf "github.com/nitsugaro/go-conf"
	jwtek "github.com/nitsugaro/go-jwte-manager"
)

func TestMain(t *testing.T) {
	goconf.LoadConfig()

	keyStorage := jwtek.GetKeyStorage()

	keyStorage.Save(jwtek.NewECKey(jwtek.ES256, jwtek.SIG, elliptic.P256(), jwtek.OIDC_PURPOSE))

	keys, total := keyStorage.Query(
		jwtek.ChainCondition(jwtek.IsActive, jwtek.IsNotExpired, jwtek.IsAlg(jwtek.ALG(jwtek.ES256)), jwtek.IsPurpose("OIDC"), jwtek.IsSigUse),
		2,
	)

	fmt.Println(keys, total)

	ecPrivkey, _ := keyStorage.Load("4fbbd0aa-9afa-40e4-9efb-9693a848899e")
	rsaKey384, _ := keyStorage.Load("ffb09871-5bec-4bc8-ac3d-b941675e2494")
	rsaPrivKey := rsaKey384.GetValue().(*rsa.PrivateKey)

	token, _ := jwt.NewBuilder().
		Issuer("yo").
		Subject("usuario123").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(1 * time.Minute)).
		Build()

	// 3. Firmar (JWS compact)
	signedJWT, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, ecPrivkey.GetValue()))
	if err != nil {
		panic(err)
	}
	fmt.Println("🔏 JWT firmado (JWS):", string(signedJWT))

	header := jwe.NewHeaders()
	header.Set("iat", time.Now().Unix())
	header.Set("exp", time.Now().Add(time.Minute*1).Unix())

	// 4. Encriptar (JWE compact)
	encrypted, err := jwe.Encrypt(signedJWT,
		jwe.WithKey(jwa.RSA_OAEP_256, &rsaPrivKey.PublicKey),
		jwe.WithContentEncryption(jwa.A256GCM),
		jwe.WithProtectedHeaders(header),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("\n🔐 JWT encriptado (JWE):", string(encrypted))

	// 5. Desencriptar
	decrypted, err := jwe.Decrypt(encrypted, jwe.WithKey(jwa.RSA_OAEP_256, rsaPrivKey))
	if err != nil {
		panic(err)
	}
	fmt.Println("\n🔓 JWT desencriptado:", string(decrypted))

	// 7. Parsear el JWT y ver los claims
	parsedToken, err := jwt.Parse(decrypted, jwt.WithKey(jwa.ES256, (ecPrivkey.GetValue().(*ecdsa.PrivateKey))), jwt.WithValidate(true))
	if err != nil {
		panic(err)
	}

	fmt.Println("\n✅ Claims:")
	fmt.Println("  Subject:", parsedToken.Subject())
	fmt.Println("  Issuer:", parsedToken.Issuer())
	fmt.Println("  Exp:", parsedToken.Expiration())
}
