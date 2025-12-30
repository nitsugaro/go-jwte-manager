package jwtek

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nitsugaro/go-nstore"
	goutils "github.com/nitsugaro/go-utils"
	"github.com/nitsugaro/go-utils/crypto"
	"github.com/nitsugaro/go-utils/encoding"
)

type ResponseJwks struct {
	Keys []goutils.DefaultMap `json:"keys"`
}

type Jwks struct {
	*nstore.Metadata

	Jwks []goutils.DefaultMap `json:"jwks"`
	Iat  int64                `json:"iat"`
}

type ExternalJwkStorage struct {
	*nstore.NStorage[*Jwks]

	CacheSeconds int64 `json:"cache_seconds"`
}

var httpClient, _ = goutils.NewHttpClient(&goutils.ClientConfig{Timeout: 20 * time.Second})

func (sj *ExternalJwkStorage) LoadOrSearch(uri string) ([]goutils.DefaultMap, error) {
	uriHash := encoding.EncodeBase64URL((crypto.HashSHA1(uri)))

	if jwkCache, err := sj.Load(uriHash); err == nil && time.Now().Unix()-jwkCache.Iat < sj.CacheSeconds {
		return jwkCache.Jwks, nil
	}

	res, err := httpClient.Request("GET", uri, nil, nil)
	if err != nil {
		return nil, err
	}

	var responseJwkUri ResponseJwks
	if err := json.Unmarshal(res.Body, &responseJwkUri); err != nil {
		return nil, err
	}

	jwks := &Jwks{
		Metadata: &nstore.Metadata{ID: uriHash},
		Jwks:     responseJwkUri.Keys,
		Iat:      time.Now().Unix(),
	}

	if err := sj.Save(jwks); err != nil {
		return jwks.Jwks, fmt.Errorf("cannot save jwks from uri: '%s'", err.Error())
	} else {
		return jwks.Jwks, nil
	}
}
