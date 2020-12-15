package jwx

import (
	"encoding/json"
	"errors"
	"gopkg.in/square/go-jose.v2"
)

var (
	ErrInvalidJwxToken   = errors.New("invalid jwt/jwe token")
	ErrNoVerificationKey = errors.New("failed to resolve key to verify signature")
	ErrNoDecryptionKey   = errors.New("failed to resolve decryption key")
)

// Decode decodes the claims of the given JWT/JWE token into the provided destination object.
//
// The decoding process is driven by both the token and the caller input. The hint algorithms suggests whether
// to perform decryption operation and/or signature verification operations, or not. When the algorithm is not IsNone,
// the corresponding stage is performed. Keys will be resolved against the verification and/or decryption key sets
// based on values present in the JWS/JWE headers. The "kid" header is given precedence to the "alg" header. In the end,
// the decrypted and verified payload is deserialized into the destination object as JSON.
func Decode(jwx string, verifyJwks *KeySet, decryptJwks *KeySet, hint Algs, dest interface{}) error {
	var raw = []byte(jwx)

	if verifyJwks == nil {
		verifyJwks = NewKeySet()
	}
	if decryptJwks == nil {
		decryptJwks = NewKeySet()
	}

	if !IsNone(hint.Encrypt) && !IsNone(hint.Encode) {
		jwe, err := jose.ParseEncrypted(string(raw))
		if err != nil {
			return err
		}

		key, err := func() (*Key, error) {
			switch {
			case len(jwe.Header.KeyID) > 0:
				if k, ok := decryptJwks.KeyById(jwe.Header.KeyID); ok {
					return k, nil
				} else {
					return nil, ErrNoDecryptionKey
				}
			case len(jwe.Header.Algorithm) > 0:
				if k, ok := decryptJwks.KeyForEncryption(jwe.Header.Algorithm); ok {
					return k, nil
				} else {
					return nil, ErrNoDecryptionKey
				}
			default:
				return nil, ErrNoDecryptionKey
			}
		}()
		if err != nil {
			return err
		}

		if decrypted, err := jwe.Decrypt(key.Raw()); err != nil {
			return err
		} else {
			raw = decrypted
		}
	}

	if !IsNone(hint.Sig) {
		jws, err := jose.ParseSigned(string(raw))
		if err != nil {
			return err
		}

		key, err := func() (*Key, error) {
			if len(jws.Signatures) != 1 {
				return nil, ErrInvalidJwxToken
			}

			hd := jws.Signatures[0].Header

			switch {
			case len(hd.KeyID) > 0:
				if k, ok := verifyJwks.KeyById(hd.KeyID); ok {
					return k, nil
				} else {
					return nil, ErrNoVerificationKey
				}
			case len(hd.Algorithm) > 0:
				if k, ok := verifyJwks.KeyForSigning(hd.Algorithm); ok {
					return k, nil
				} else {
					return nil, ErrNoVerificationKey
				}
			default:
				return nil, ErrNoVerificationKey
			}
		}()
		if err != nil {
			return err
		}

		if verified, err := jws.Verify(key.ToPublic().Raw()); err != nil {
			return err
		} else {
			raw = verified
		}
	}

	return json.Unmarshal(raw, dest)
}
