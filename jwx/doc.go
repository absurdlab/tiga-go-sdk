// Package jwx provides a thin wrapper layer around gopkg.in/square/go-jose.v2 to provide JOSE related operations
// in the OpenID Connect context.
//
// The features provided includes:
// - wrapper around jose.JSONWebKey and jose.JSONWebKeySet to provider convenient parsing and querying capabilities.
// - Claims interface to allow custom implementation of JWT claims, with a default map based implementation.
// - Expect functions to allow custom validation rules, with out-of-box implementations for standard claims.
// - KeySource functions to allow custom logic to locate a Key, with out-of-box implementation for common scenarios.
// - Encode and Decode functions to handle converting to and from a JWT/JWX token.
package jwx
