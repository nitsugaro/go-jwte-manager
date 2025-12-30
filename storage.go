package jwtek

import (
	goconf "github.com/nitsugaro/go-conf"
	"github.com/nitsugaro/go-nstore"
)

type KeyStorage nstore.NStorage[*Key]

var keyStorage *nstore.NStorage[*Key]

var externalJwkStorage *ExternalJwkStorage

func GetKeyStorage() *nstore.NStorage[*Key] {
	return keyStorage
}

func GetExternalJwkStorage() *ExternalJwkStorage {
	return externalJwkStorage
}

func GetPublicJwk() []interface{} {
	jwks := []interface{}{}
	for _, key := range keyStorage.ListOfCache() {
		if !key.IsHmac() && key.Purpose == OIDC_PURPOSE {
			if jwk, err := key.GetPublicJWK(); err == nil {
				jwks = append(jwks, jwk)
			}
		}
	}

	return jwks
}

func init() {
	goconf.OnLoad(func() {
		storage, err := nstore.New[*Jwks](goconf.GetOpField("jwtek.external_jwks.folder", "jwtek/jwks"))
		if err != nil {
			panic(err.Error())
		}

		externalJwkStorage = &ExternalJwkStorage{NStorage: storage, CacheSeconds: goconf.GetOpField("jwtek.external_jwks.cache_seconds", int64(60))}

		keyStorage, _ = nstore.New[*Key](goconf.GetOpField("jwtek.keys.folder", "jwtek/keys"))

		if err := keyStorage.LoadFromDisk(); err != nil {
			panic(err.Error())
		}

		if len(keyStorage.ListOfCache()) == 0 && goconf.GetOpField("jwtek.keys.generate_defaults", true) {
			initKeys()
		} else {
			for _, key := range keyStorage.ListOfCache() {
				key.init()
			}
		}
	})
}
