package oidc

import "errors"

const (
	SubjectTypePublic   = "public"
	SubjectTypePairwise = "pairwise"
)

var (
	// ErrInvalidSubjectType indicates the given subject_type is not valid
	ErrInvalidSubjectType = errors.New("subject_type is invalid")

	// ValidSubjectType is the validation function for strings containing a subject type.
	ValidSubjectType = func(s string) error {
		switch s {
		case SubjectTypePublic, SubjectTypePairwise:
			return nil
		default:
			return ErrInvalidSubjectType
		}
	}
)
