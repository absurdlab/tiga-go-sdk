package oidc

import "errors"

const (
	ClientSecretBasic = "client_secret_basic"
	ClientSecretPost  = "client_secret_post"
	ClientSecretJwt   = "client_secret_jwt"
	PrivateKeyJwt     = "private_key_jwt"
	TokenAuthNone     = "none"
)

var (
	// InvalidTokenEndpointAuthMethod indicates an invalid token endpoint authentication method
	ErrInvalidTokenEndpointAuthMethod = errors.New("token_endpoint_auth_method is invalid")

	// ErrInvalidTokenEndpointAuthMethod is a validation function to check if the given string contains
	// a valid client token endpoint authentication method.
	ValidTokenEndpointAuthMethod = func(s string) error {
		switch s {
		case ClientSecretBasic, ClientSecretPost, ClientSecretJwt, PrivateKeyJwt, TokenAuthNone:
			return nil
		default:
			return ErrInvalidTokenEndpointAuthMethod
		}
	}
)
