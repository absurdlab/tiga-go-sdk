package jwx

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"gopkg.in/square/go-jose.v2"
)

// Key provides the features of a JSONWebKey.
type Key struct {
	key *jose.JSONWebKey
}

// Id returns the id of the key.
func (k *Key) Id() string {
	return k.key.KeyID
}

// Use returns the expected usage of the key.
func (k *Key) Use() string {
	return k.key.Use
}

// Alg returns the algorithm of the key.
func (k *Key) Alg() string {
	return k.key.Algorithm
}

// IsSymmetric returns true if the underlying key uses symmetric algorithms (i.e. HS256)
func (k *Key) IsSymmetric() bool {
	_, ok := k.key.Key.([]byte)
	return ok
}

// IsPublic returns true if the underlying key only has the public portion of the non-symmetric
// keys. This method applies only to non-symmetric keys (as in IsSymmetric returns false), its
// return true is irrelevant for symmetric keys.
func (k *Key) IsPublic() bool {
	switch k.Raw().(type) {
	case ed25519.PublicKey, *ecdsa.PublicKey, *rsa.PublicKey:
		return true
	default:
		return false
	}
}

// Raw returns the underlying cryptographic key.
func (k *Key) Raw() interface{} {
	return k.key.Key
}

// ToPublic returns a new Key with only the public portion of the underlying key. This method
// shall return the same Key if the key is already public or is symmetric.
func (k *Key) ToPublic() *Key {
	if k.IsPublic() || k.IsSymmetric() {
		return k
	}

	return &Key{
		key: &jose.JSONWebKey{
			Key: func() interface{} {
				raw := k.Raw()
				switch raw.(type) {
				case ed25519.PrivateKey:
					return raw.(ed25519.PrivateKey).Public()
				case *ecdsa.PrivateKey:
					return raw.(*ecdsa.PrivateKey).Public()
				case *rsa.PrivateKey:
					return raw.(*rsa.PrivateKey).Public()
				default:
					panic("public key conversion is not supported for this key type")
				}
			}(),
			KeyID:     k.Id(),
			Algorithm: k.Alg(),
			Use:       k.Use(),
		},
	}
}

// KeySource is a function that can produce a Key and its corresponding algorithm specs.
type KeySource func() (*Key, Algs, bool)
