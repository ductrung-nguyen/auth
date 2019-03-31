package auth

import "errors"

var (
	// ErrInvalidPassword invalid password error
	ErrInvalidPassword = errors.New("invalid password")
	// ErrInvalidAccount invalid account error
	ErrInvalidAccount = errors.New("invalid account")
	// ErrUnauthorized unauthorized error
	ErrUnauthorized = errors.New("Unauthorized")

	// ErrAccountExisted unauthorized error
	ErrAccountExisted = errors.New("error.account.existed")
)
