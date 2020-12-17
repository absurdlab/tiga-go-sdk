package oidc

import "errors"

const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeImplicit          = "implicit"
	GrantTypePassword          = "password"
	GrantTypeClientCredentials = "client_credentials"
	GrantTypeRefreshToken      = "refresh_token"
)

var (
	// AllGrantTypes is a string array containing all valid grant types
	AllGrantTypes = []string{
		GrantTypeAuthorizationCode,
		GrantTypeImplicit,
		GrantTypePassword,
		GrantTypeClientCredentials,
		GrantTypeRefreshToken,
	}

	// ErrInvalidGrantType indicates an invalid grant type value.
	ErrInvalidGrantType = errors.New("grant_type is invalid")

	// ValidGrantType is the validation function for a string containing a grant type.
	ValidGrantType = func(s string) error {
		switch s {
		case GrantTypeAuthorizationCode,
			GrantTypeImplicit,
			GrantTypePassword,
			GrantTypeClientCredentials,
			GrantTypeRefreshToken:
			return nil
		default:
			return ErrInvalidGrantType
		}
	}
)
