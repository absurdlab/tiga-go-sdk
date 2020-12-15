package oidc

import "errors"

const (
	ClaimTypeNormal      = "normal"
	ClaimTypeAggregated  = "aggregated"
	ClaimTypeDistributed = "distributed"
)

var (
	// ErrInvalidClaimType indicates claim_type is invalid.
	ErrInvalidClaimType = errors.New("claim_type is invalid")

	// ValidClaimType is the validation function for claim_type.
	ValidClaimType = func(s string) error {
		switch s {
		case ClaimTypeNormal, ClaimTypeAggregated, ClaimTypeDistributed:
			return nil
		default:
			return ErrInvalidClaimType
		}
	}
)
