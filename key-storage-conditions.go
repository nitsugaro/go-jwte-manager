package jwtek

import (
	"time"

	"github.com/nitsugaro/go-nstore"
)

func IsHmacAlg(k *Key) bool {
	return k.IsHmac()
}

func IsRsaAlg(k *Key) bool {
	return k.IsRsa()
}

func IsEcAlg(k *Key) bool {
	return k.IsEc()
}

func IsEdAlg(k *Key) bool {
	return k.IsEd()
}

func IsSigUse(k *Key) bool {
	return k.Use == SIG
}

func IsEncUse(k *Key) bool {
	return k.Use == ENC
}

func IsAlg(alg ALG) nstore.ConditionalFunc[*Key] {
	return func(k *Key) bool {
		return k.Alg == alg
	}
}

func IsPurpose(purpose string) nstore.ConditionalFunc[*Key] {
	return func(k *Key) bool {
		return k.Purpose == purpose
	}
}

func IsNotExpired(k *Key) bool {
	return k.Exp == 0 || k.Exp > time.Now().Unix()
}

func IsActive(k *Key) bool {
	return k.Active
}

func ChainCondition(queries ...nstore.ConditionalFunc[*Key]) nstore.ConditionalFunc[*Key] {
	return func(k *Key) bool {
		for _, query := range queries {
			if !query(k) {
				return false
			}
		}

		return true
	}
}

func CondToSign(alg ALG) nstore.ConditionalFunc[*Key] {
	return ChainCondition(IsAlg(alg), IsActive, IsNotExpired, IsSigUse)
}

func CondToEncrypt(alg ALG) nstore.ConditionalFunc[*Key] {
	return ChainCondition(IsAlg(alg), IsActive, IsNotExpired, IsEncUse)
}
