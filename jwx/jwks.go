package jwx

import (
	"encoding/json"
	"gopkg.in/square/go-jose.v2"
	"io"
	"time"
)

// NewKeySet creates a new key set with the given keys.
func NewKeySet(keys ...*Key) *KeySet {
	s := &KeySet{ks: map[string]*Key{}}
	for _, key := range keys {
		s.ks[key.Id()] = key
	}
	return s
}

// ReadKeySet create new KeySet with data from the reader
func ReadKeySet(reader io.Reader) (*KeySet, error) {
	gojoseJwks := new(jose.JSONWebKeySet)
	err := json.NewDecoder(reader).Decode(&gojoseJwks)
	if err != nil {
		return nil, err
	}

	set := &KeySet{ks: map[string]*Key{}}
	for _, k := range gojoseJwks.Keys {
		/*
		 * !Important!
		 * -----------
		 * copy k value onto local stack
		 * before k changes in the next iteration.
		 */
		k0 := k
		jwk := &Key{key: &k0}
		set.ks[jwk.Id()] = jwk
	}

	return set, nil
}

// KeySet is a set of Key. Also known as JSONWebKey Set.
type KeySet struct {
	ks map[string]*Key
}

// Count returns the number of keys in the set.
func (s *KeySet) Count() int {
	return len(s.ks)
}

// KeyById finds a Key by its id value.
func (s *KeySet) KeyById(kid string) (*Key, bool) {
	k, ok := s.ks[kid]
	if !ok {
		return nil, false
	}
	return k, true
}

// KeyForSigning find a key for signing with the given algorithm. If multiple signing keys with the same
// algorithm exists in the set, a rotation factor is computed to pick one based on the current time.
func (s *KeySet) KeyForSigning(alg string) (*Key, bool) {
	var candidates []*Key

	for _, k := range s.ks {
		if k.Use() == UseSig && k.Alg() == alg {
			candidates = append(candidates, k)
		}
	}

	switch len(candidates) {
	case 0:
		return nil, false
	case 1:
		return candidates[0], true
	default:
		return candidates[time.Now().Unix()%int64(len(candidates))], true
	}
}

// KeyForEncryption find a key for encryption with the given algorithm. The returned key may be a private key, in
// which case, caller needs to convert to a public key before use.
//
// If multiple encryption keys with the same algorithm exists in the set, a rotation factor is computed to pick one
// based on the current time.
func (s *KeySet) KeyForEncryption(alg string) (*Key, bool) {
	var candidates []*Key

	for _, k := range s.ks {
		if k.Use() == UseEnc && k.Alg() == alg {
			candidates = append(candidates, k)
		}
	}

	switch len(candidates) {
	case 0:
		return nil, false
	case 1:
		return candidates[0], true
	default:
		return candidates[time.Now().Unix()%int64(len(candidates))], true
	}
}

// ToPublic returns a new KeySet with only public asymmetric keys so that it is read to be shared.
func (s *KeySet) ToPublic() *KeySet {
	var pubKeys []*Key
	for _, each := range s.ks {
		if !each.IsSymmetric() {
			pubKeys = append(pubKeys, each.ToPublic())
		}
	}
	return NewKeySet(pubKeys...)
}

func (s *KeySet) MarshalJSON() ([]byte, error) {
	gojoseJwks := &jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}}
	for _, each := range s.ks {
		gojoseJwks.Keys = append(gojoseJwks.Keys, *each.key)
	}
	return json.Marshal(gojoseJwks)
}

func (s *KeySet) UnmarshalJSON(bytes []byte) error {
	goJoseJwks := new(jose.JSONWebKeySet)
	if err := json.Unmarshal(bytes, &goJoseJwks); err != nil {
		return err
	}

	if s.ks == nil {
		s.ks = map[string]*Key{}
	}

	for _, each := range goJoseJwks.Keys {
		jwk := each // copy it onto the stack before referencing it, this is important!
		k := &Key{key: &jwk}
		s.ks[k.Id()] = k
	}

	return nil
}

var (
	// SignatureKeyById returns a KeySource which find a signature Key by its key id.
	SignatureKeyById = func(kid string, jwks *KeySet) KeySource {
		return func() (*Key, Algs, bool) {
			key, ok := jwks.KeyById(kid)
			if !ok || key.Use() != UseSig {
				return nil, Algs{}, false
			}
			return key, Algs{Sig: key.Alg()}, true
		}
	}
	// SignatureKeyByAlg returns a KeySource which finds a signature Key by algorithm.
	SignatureKeyByAlg = func(alg string, jwks *KeySet) KeySource {
		if IsNone(alg) {
			return SkipKeySource
		}
		return func() (*Key, Algs, bool) {
			key, ok := jwks.KeyForSigning(alg)
			if !ok {
				return nil, Algs{}, false
			}
			return key, Algs{Sig: alg}, true
		}
	}
	// EncryptionKeyByAlg returns a KeySource which finds a encryption Key by algorithm.
	EncryptionKeyByAlg = func(encryptAlg, encodeAlg string, jwks *KeySet) KeySource {
		if IsNone(encryptAlg) || IsNone(encodeAlg) {
			return SkipKeySource
		}
		return func() (*Key, Algs, bool) {
			key, ok := jwks.KeyForEncryption(encryptAlg)
			if !ok {
				return nil, Algs{}, false
			}
			return key, Algs{Encrypt: encryptAlg, Encode: encodeAlg}, true
		}
	}
	// SkipKeySource returns a KeySource that whose Algs return value IsNone, and shall be skipped.
	SkipKeySource KeySource = func() (*Key, Algs, bool) {
		return nil, Algs{}, true
	}
)
