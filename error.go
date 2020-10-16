package strobe

import "errors"

var (
	// ErrAuthenticationFailed is the error returned by RecvMAC when MAC is invalid
	ErrAuthenticationFailed = errors.New("authentication failed")
	// ErrInvalidSecurityLevel is the error returned by New when the specified security level is
	// unsupported
	ErrInvalidSecurityLevel = errors.New("only 128 or 256 bit security is supported")
)
