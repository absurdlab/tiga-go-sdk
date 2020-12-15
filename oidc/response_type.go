package oidc

import (
	"errors"
	"github.com/absurdlab/tiga-go-sdk/internal"
	"strings"
)

const (
	ResponseTypeCode    = "code"
	ResponseTypeToken   = "token"
	ResponseTypeIdToken = "id_token"
)

var (
	// AllResponseTypeCombos is an array containing all combinations of response types.
	AllResponseTypeCombos = []string{
		"code",
		"token",
		"id_token",
		"code token",
		"code id_token",
		"token id_token",
		"code token id_token",
	}

	// ErrInvalidResponseType indicates an invalid response type value.
	ErrInvalidResponseType = errors.New("response_type is invalid")

	// ValidCompositeResponseType is the validation function for a string containing
	// a single response type or multiple response types delimited by space.
	ValidCompositeResponseType = func(s string) error {
		tokens := internal.NewSet(strings.Fields(s)...)

		if len(tokens) == 0 {
			return ErrInvalidResponseType
		}

		if ok := tokens.All(func(element string) bool {
			switch element {
			case ResponseTypeCode, ResponseTypeToken, ResponseTypeIdToken:
				return true
			default:
				return false
			}
		}); ok {
			return nil
		}

		return ErrInvalidResponseType
	}
)
