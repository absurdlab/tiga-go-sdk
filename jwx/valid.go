package jwx

import "errors"

var (
	// ErrInvalidSignatureAlg indicates the used signature algorithm is invalid.
	ErrInvalidSignatureAlg = errors.New("signature algorithm is invalid")
	// ErrInvalidEncryptionAlg indicates the used encryption algorithm is invalid.
	ErrInvalidEncryptionAlg = errors.New("encryption algorithm is invalid")
	// ErrInvalidEncryptionEnc indicates the used encryption encoding is invalid.
	ErrInvalidEncryptionEnc = errors.New("encryption encoding is invalid")

	// ValidSignatureAlg is a validation function that checks if the given string is a valid JWA
	// signature algorithm. This function rejects empty string or "none".
	ValidSignatureAlg = func(s string) error {
		switch s {
		case HS256, HS384, HS512,
			RS256, RS384, RS512,
			PS256, PS384, PS512,
			ES256, ES384, ES512:
			return nil
		default:
			return ErrInvalidSignatureAlg
		}
	}
	// ValidOptionalSignatureAlg is a validation function that checks if the given string is a valid JWA
	// signature algorithm. This function accepts empty string or "none".
	ValidOptionalSignatureAlg = func(s string) error {
		if IsNone(s) {
			return nil
		}
		return ValidSignatureAlg(s)
	}
	// ValidEncryptionAlg is a validation function that checks if the given string is a valid JWA
	// encryption algorithm. This function rejects empty string or "none".
	ValidEncryptionAlg = func(s string) error {
		switch s {
		case ED25519,
			RSA1_5, RSA_OAEP, RSA_OAEP_256,
			A128KW, A192KW, A256KW,
			DIRECT,
			ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW,
			A128GCMKW, A192GCMKW, A256GCMKW,
			PBES2_HS256_A128KW, PBES2_HS384_A192KW, PBES2_HS512_A256KW:
			return nil
		default:
			return ErrInvalidEncryptionAlg
		}
	}
	// ValidEncryptionAlgOptional is a validation function that checks if the given string is a valid JWA
	// encryption algorithm. This function accepts empty string or "none".
	ValidOptionalEncryptionAlg = func(s string) error {
		if IsNone(s) {
			return nil
		}
		return ValidEncryptionAlg(s)
	}
	// ValidEncryptionEnc is a validation function that checks if the given string is a valid JWA
	// encryption encoding. This function rejects empty string or "none".
	ValidEncryptionEnc = func(s string) error {
		switch s {
		case A128CBC_HS256, A192CBC_HS384, A256CBC_HS512,
			A128GCM, A192GCM, A256GCM:
			return nil
		default:
			return ErrInvalidEncryptionEnc
		}
	}
	// ValidEncryptionEncOptional is a validation function that checks if the given string is a valid JWA
	// encryption encoding. This function accepts empty string or "none".
	ValidOptionalEncryptionEnc = func(s string) error {
		if IsNone(s) {
			return nil
		}
		return ValidEncryptionEnc(s)
	}
)
