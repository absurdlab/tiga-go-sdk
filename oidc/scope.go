package oidc

import (
	"errors"
	"github.com/absurdlab/tiga-go-sdk/internal"
	"strings"
)

// Well known scopes
const (
	ScopeOpenId        = "openid"
	ScopeOfflineAccess = "offline_access"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopePhoneNumber   = "phone_number"
	ScopeAddress       = "address"
)

// Internally used scopes.
const (
	ScopeTigaLogin         = "tiga.login"
	ScopeTigaSelectAccount = "tiga.select_account"
	ScopeTigaConsent       = "tiga.consent"
)

var (
	ErrInvalidScope = errors.New("scope is invalid")

	// ValidSingleScope is the validation function for strings containing a single scope.
	ValidSingleScope = func(s string) error {
		for _, r := range s {
			if r >= '!' && r <= '~' && r != '"' && r != '\\' {
				continue
			} else {
				return ErrInvalidScope
			}
		}
		return nil
	}

	// ValidCompositeScope is the validation function for strings containing one or more scopes.
	ValidCompositeScope = func(s string) error {
		scopes := internal.NewSet(strings.Fields(s)...)

		if len(scopes) == 0 {
			return ErrInvalidScope
		}

		if ok := scopes.All(func(element string) bool {
			return ValidSingleScope(element) == nil
		}); ok {
			return nil
		}

		return ErrInvalidScope
	}
)
