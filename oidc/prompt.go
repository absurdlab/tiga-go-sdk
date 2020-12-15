package oidc

import (
	"errors"
	"github.com/absurdlab/tiga-go-sdk/internal"
	"strings"
)

const (
	PromptLogin         = "login"
	PromptSelectAccount = "select_account"
	PromptConsent       = "consent"
	PromptNone          = "none"
)

var (
	// ErrInvalidPrompt indicates the prompt parameter is invalid
	ErrInvalidPrompt = errors.New("invalid prompt")

	// ValidPrompt is a validation function to check if the string is a valid prompt.
	ValidPrompt = func(s string) error {
		switch s {
		case PromptLogin, PromptSelectAccount, PromptConsent, PromptNone:
			return nil
		default:
			return ErrInvalidPrompt
		}
	}

	// ValidCompositePrompt is a validation function to check if the space delimited
	// prompt has a valid combination. Note that this function does not ensure all elements
	// contained is a valid prompt, only checks the combination.
	ValidCompositePrompt = func(prompt string) func() error {
		return func() error {
			prompts := internal.NewSet(strings.Fields(prompt)...)
			switch {
			case prompts.Contains(PromptNone) && len(prompts) > 1:
				return ErrInvalidPrompt
			case prompts.Contains(PromptLogin) && prompts.Contains(PromptSelectAccount):
				return ErrInvalidPrompt
			default:
				return nil
			}
		}
	}
)
