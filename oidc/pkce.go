package oidc

import "errors"

const (
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
)

var (
	// ErrInvalidCodeChallengeMethod indicates an invalid code challenge method value.
	ErrInvalidCodeChallengeMethod = errors.New("code_challenge_method is invalid")

	// ValidCodeChallengeMethod is the validation function for a string containing a code challenge method.
	ValidCodeChallengeMethod = func(s string) error {
		switch s {
		case CodeChallengeMethodPlain, CodeChallengeMethodS256:
			return nil
		default:
			return ErrInvalidCodeChallengeMethod
		}
	}
)
