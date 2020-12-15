package oidc

import "errors"

const (
	ResponseModeQuery    = "query"
	ResponseModeFragment = "fragment"
)

var (
	// ErrInvalidResponseMode indicates response mode is invalid.
	ErrInvalidResponseMode = errors.New("response_mode is invalid")

	// ValidResponseType is the validation function for a string response mode.
	ValidResponseMode = func(s string) error {
		switch s {
		case ResponseModeQuery, ResponseModeFragment:
			return nil
		default:
			return ErrInvalidResponseMode
		}
	}
)
