package jwk

import "errors"

var (
	ErrUnsopportedCurve = errors.New("unsupported curve")
	ErrNotFoundJwk      = errors.New("not found jwk")
	ErrInvalidJwk       = errors.New("invalid jwk")
	ErrInvalidAlg       = errors.New("invalid alg")
	ErrInvalidOkpKey    = errors.New("unsupported okp key")
)
