package jwx

import (
	"encoding/json"
	"errors"
	"gopkg.in/square/go-jose.v2"
)

var (
	ErrNoSigningKey    = errors.New("failed to resolve signing key")
	ErrNoEncryptionKey = errors.New("failed to resolve encryption key")
)

// EncodeToString is a convenience wrapper around Encode. It returns the encoded result in string format.
func EncodeToString(sig KeySource, enc KeySource, payload interface{}) (string, error) {
	raw, err := Encode(sig, enc, payload)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// Encode encodes the given payload to a JWT or a JWE token.
//
// The payload is normally serialized into JSON before performing signing and/or encryption operations. However, the
// serialization can be skipped by providing the payload as []byte, json.RawMessage or string, which indicates to the
// function that the payload is already serialized.
//
// The signature KeySource sig and encryption KeySource enc controls the signing and encryption operations. Both stage
// can be skipped by providing nil or SkipKeySource as the KeySource for the corresponding stage. Normal usages would
// be to skip none or just one of the stages. However, it is fine to skip both stages, which simply reduces this function
// to a JSON encoding function.
func Encode(sig KeySource, enc KeySource, payload interface{}) ([]byte, error) {
	if sig == nil {
		sig = SkipKeySource
	}
	if enc == nil {
		enc = SkipKeySource
	}

	var raw []byte
	{
		switch payload.(type) {
		case []byte, json.RawMessage:
			raw = payload.([]byte)
		case string:
			raw = []byte(payload.(string))
		default:
			if rs, err := json.Marshal(payload); err != nil {
				return nil, err
			} else {
				raw = rs
			}
		}
	}

	sigKey, algs, ok := sig()
	if !ok {
		return nil, ErrNoSigningKey
	}
	if !IsNone(algs.Sig) {
		signer, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(algs.Sig),
			Key:       sigKey.Raw(),
		}, (&jose.SignerOptions{}).WithHeader("kid", sigKey.Id()))
		if err != nil {
			return nil, err
		}

		jws, err := signer.Sign(raw)
		if err != nil {
			return nil, err
		}

		compact, err := jws.CompactSerialize()
		if err != nil {
			return nil, err
		}

		raw = []byte(compact)
	}

	encKey, algs, ok := enc()
	if !ok {
		return nil, ErrNoEncryptionKey
	}
	if !IsNone(algs.Encrypt) && !IsNone(algs.Encode) {
		encrypter, err := jose.NewEncrypter(jose.ContentEncryption(algs.Encode), jose.Recipient{
			Algorithm: jose.KeyAlgorithm(algs.Encrypt),
			Key:       encKey.ToPublic().Raw(),
			KeyID:     encKey.Id(),
		}, (&jose.EncrypterOptions{}).WithHeader("kid", encKey.Id()))
		if err != nil {
			return nil, err
		}

		jwe, err := encrypter.Encrypt(raw)
		if err != nil {
			return nil, err
		}

		compact, err := jwe.CompactSerialize()
		if err != nil {
			return nil, err
		}

		raw = []byte(compact)
	}

	return raw, nil
}
