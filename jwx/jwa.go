package jwx

import "gopkg.in/square/go-jose.v2"

// Signature algorithms
const (
	HS256 = string(jose.HS256)
	HS384 = string(jose.HS384)
	HS512 = string(jose.HS512)
	RS256 = string(jose.RS256)
	RS384 = string(jose.RS384)
	RS512 = string(jose.RS512)
	PS256 = string(jose.PS256)
	PS384 = string(jose.PS384)
	PS512 = string(jose.PS512)
	ES256 = string(jose.ES256)
	ES384 = string(jose.ES384)
	ES512 = string(jose.ES512)
)

// Key algorithms
// Also known as "encryption algorithm" in OIDC context.
const (
	ED25519            = string(jose.ED25519)
	RSA1_5             = string(jose.RSA1_5)
	RSA_OAEP           = string(jose.RSA_OAEP)
	RSA_OAEP_256       = string(jose.RSA_OAEP_256)
	A128KW             = string(jose.A128KW)
	A192KW             = string(jose.A192KW)
	A256KW             = string(jose.A256KW)
	DIRECT             = string(jose.DIRECT)
	ECDH_ES            = string(jose.ECDH_ES)
	ECDH_ES_A128KW     = string(jose.ECDH_ES_A128KW)
	ECDH_ES_A192KW     = string(jose.ECDH_ES_A192KW)
	ECDH_ES_A256KW     = string(jose.ECDH_ES_A256KW)
	A128GCMKW          = string(jose.A128GCMKW)
	A192GCMKW          = string(jose.A192GCMKW)
	A256GCMKW          = string(jose.A256GCMKW)
	PBES2_HS256_A128KW = string(jose.PBES2_HS256_A128KW)
	PBES2_HS384_A192KW = string(jose.PBES2_HS384_A192KW)
	PBES2_HS512_A256KW = string(jose.PBES2_HS512_A256KW)
)

// Encryption algorithms.
// Also known as "content encoding algorithm" in OIDC context.
const (
	A128CBC_HS256 = string(jose.A128CBC_HS256)
	A192CBC_HS384 = string(jose.A192CBC_HS384)
	A256CBC_HS512 = string(jose.A256CBC_HS512)
	A128GCM       = string(jose.A128GCM)
	A192GCM       = string(jose.A192GCM)
	A256GCM       = string(jose.A256GCM)
)

// IsNone returns true if the algorithm is empty or has value "none". Algorithm
// values that are none should be treated as absent, and use defaults if necessary.
func IsNone(alg string) bool {
	return len(alg) == 0 || alg == "none"
}

// Algs is a pack of algorithms
type Algs struct {
	// Sig is the signature algorithm
	Sig string
	// Encrypt is the encryption algorithm
	Encrypt string
	// Encode is the encryption encoding
	Encode string
}
