package tigasdk

import (
	"context"
	"net/http"
)

// Stub describes the client side functions provided by the SDK to communicate
// with the Tiga instance. It is included in the SDK so that client side code
// can implement it to mock Tiga during development and testing.
type Stub interface {
	// TokenByClientCredentials acquire access tokens using the client_credentials flow.
	TokenByClientCredentials(ctx context.Context, scopes []string) (*TokenResponse, error)

	// TokenByCode acquire access tokens, and optionally refresh token and id_token using the authorization_code flow.
	TokenByCode(ctx context.Context, code string, redirectURI string, scopes []string) (*TokenResponse, error)

	// TokenByRefreshToken acquire access tokens and refresh token by exchanging in existing refresh token.
	TokenByRefreshToken(ctx context.Context, refreshToken string, scopes []string) (*TokenResponse, error)

	// LoginState gets the InteractionState of the login challenge.
	LoginState(ctx context.Context, xid string) (*InteractionState, error)

	// SelectAccountState gets the InteractionState of the select account challenge.
	SelectAccountState(ctx context.Context, xid string) (*InteractionState, error)

	// ConsentState gets the InteractionState of the consent challenge.
	ConsentState(ctx context.Context, xid string) (*InteractionState, error)

	// LoginCallback posts the End-User's LoginCallback response back to Tiga.
	LoginCallback(ctx context.Context, xid string, callback *LoginCallback) (bool, error)

	// SelectAccountCallback posts the End-User's SelectAccountCallback response back to Tiga.
	SelectAccountCallback(ctx context.Context, xid string, callback *SelectAccountCallback) (bool, error)

	// ConsentCallback posts the End-User's ConsentCallback response back to Tiga.
	ConsentCallback(ctx context.Context, xid string, callback *ConsentCallback) (bool, error)

	// ResumeAuthorize redirects the http response back to the authorize resume endpoint.
	ResumeAuthorize(rw http.ResponseWriter, r *http.Request, xid string)
}

// Keep this type check as New does not
// return Stub type.
var _ Stub = (*SDK)(nil)
