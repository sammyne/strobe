package strobe

import "errors"

var (
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrInvalidSecurityLevel = errors.New("only 128 or 256 bit security is supported")

	//ErrNonContinuable       = errors.New("not continuable from previous operation")
)
