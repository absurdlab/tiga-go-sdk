package tigasdk

import (
	"encoding/json"
	"fmt"
	"github.com/absurdlab/tiga-go-sdk/jwx"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Authentication is a End-User authentication record.
type Authentication struct {
	Subject  string          `json:"subject"`
	IdpId    string          `json:"idp_id"`
	AuthTime int64           `json:"auth_time"`
	Context  json.RawMessage `json:"context,omitempty"`
}

// ScopeData describes status and details about a scope.
type ScopeData struct {
	// Status is the textual description of spec.ScopeStatus.
	// See scopeStatusMap
	Status string `json:"status"`

	// Detail is the raw data of this scope, usually describing
	// the scope of access in various displayable locales. Scope
	// detail registered with the client takes precedence, followed
	// by the default detail data about some common scopes prepared
	// by OP.
	//
	// Client registration is expected to consult consent provider
	// about the format of this data, hence, the consent provider
	// should understand the data here.
	Detail json.RawMessage `json:"detail"`
}

// Client contains the publicly displayable data of the client.
type Client struct {
	Name              string   `json:"name"`
	Contacts          []string `json:"contacts,omitempty"`
	LogoURI           string   `json:"logo_uri,omitempty"`
	PolicyURI         string   `json:"policy_uri,omitempty"`
	ClientURI         string   `json:"client_uri,omitempty"`
	TermsOfServiceURI string   `json:"tos_uri,omitempty"`
}

// OIDC contains the publicly displayable data of the OIDC request.
type OIDC struct {
	Display   string `json:"display,omitempty"`
	UILocales string `json:"ui_locales,omitempty"`
	LoginHint string `json:"login_hint,omitempty"`
	AcrValues string `json:"acr_values,omitempty"`
}

// InteractionState contains all data that an interaction provider may
// wish to know about the current state of the End-User interaction.
//
// Some data are selectively not exposed at certain stage. For instance, before
// subject is confirmed, scope data is not exposed. And when subject is confirmed,
// all other candidates authentication sessions are hidden. Client and OIDC data
// is always returned.
type InteractionState struct {
	// Subject is the subject identifier for the logged in End-User.
	// This field is optional when the login user had not be determined.
	// If OP had confirmed a login, this field will be shown along with
	// a Authentications map containing only that subject.
	Subject string `json:"subject,omitempty"`

	// Authentications contain zero or more candidates to be considered for
	// login. Login providers shall expect an empty map. Select account
	// providers shall expect a map containing one or more items. Consent
	// providers shall expect a single entry map whose key matches the Subject.
	Authentications map[string]*Authentication `json:"authentications"`

	// Scopes is the map of the requested scopes and their corresponding textual
	// status (granted|pending|rejected) and displayable detail. OP recommends
	// the consent provider display all scopes and their corresponding status to
	// the End-User so a conscious decision could be made. However, the consent
	// provider is at liberty to display any combination of the three categories.
	// Note scopes will not be shared unless Subject is determined.
	Scopes map[string]ScopeData `json:"scopes,omitempty"`

	// Client is the public sharable data about the client who made the initial
	// authorize request. OP encourages display of these data so the End-User is
	// aware which party are they granting access to.
	Client *Client `json:"client"`

	// OIDC is the public sharable data about the request itself. Interaction
	// providers are expected to adhere to the request parameters with their
	// best effort.
	OIDC *OIDC `json:"oidc"`
}

// InteractionCallback is the common elements in an interaction callback request.
type InteractionCallback struct {
	// Success is an indicator on if the interaction was positively successful.
	// If successful, operational data will be read from payload; otherwise,
	// error description will be read.
	Success bool `json:"success"`

	// Timestamp is the UNIX timestamp of the indicated event.
	Timestamp int64 `json:"timestamp"`

	// Nonce is the nonce parameter passed to the interaction provider
	// on the initial redirect. OP requires this piece of data in order
	// to prevent replay.
	Nonce string `json:"nonce"`

	// Error is the IDP specific error code indicating interaction failure.
	// It will not be returned to the client. The OP logs it for
	// debugging and auditing purposes.
	Error string `json:"error"`

	// ErrorDescription is the IDP specific description for the error
	// code. It will not be returned to the client. The OP logs it for
	// debugging and auditing purposes.
	ErrorDescription string `json:"error_description"`
}

// LoginCallback is the request payload of a callback made by login interaction provider.
type LoginCallback struct {
	InteractionCallback

	// Subject is the IDP unique identifier for the logged in user.
	Subject string `json:"subject"`

	// Amr is the list of authentication methods
	Amr []string `json:"amr"`

	// Acr is the IDP determined authentication context
	// reference.
	Acr string `json:"acr"`

	// Context is the data that login provider wishes to
	// cache at the OP and shared back to it on the next
	// interaction involving this subject. Typical usage
	// includes user avatar, nickname, etc. The data in
	// this field will be size restricted to prevent abuse.
	//
	// Note that context is only meaningful when Remember
	// option is used. If not remembered, Context data is
	// lost.
	Context json.RawMessage `json:"context"`

	// Remember is the number of seconds to remember this
	// authentication, which directly translates to the
	// authentication session validity period. If it is
	// non-positive, it will be treated as not remembered.
	Remember int64 `json:"remember"`
}

// SelectAccountCallback is the request payload of a callback made by select account interaction provider.
type SelectAccountCallback struct {
	InteractionCallback

	// SelectId is the id of the selected authentication.
	SelectedId string `json:"subject"`
}

// ConsentCallback is the request payload of a callback made by consent interaction provider.
type ConsentCallback struct {
	InteractionCallback

	// GrantedScopes are the list of scopes that the user has granted access
	// to the client. The OP must verify that these scopes had indeed been
	// requested. Scopes included here are those the End-User had explicitly
	// granted access to, no matter their previous status. These scopes will
	// be marked as granted in the session.
	GrantedScopes []string `json:"granted_scopes"`

	// RejectedScopes are the list of scopes that the user has rejected. The OP
	// must verify that these scopes had indeed been requested.  Scope included
	// here are those the End-User had explicitly rejected access to, for instance,
	// by pressing the "Deny" button, or by unchecking the checkbox. These scopes
	// will be marked as rejected in the session.
	//
	// If a scope is both granted and rejected, rejection takes precedence.
	RejectedScopes []string `json:"rejected_scopes"`

	// Ephemeral marks this response as one-time only. By default, granted scopes
	// will be recorded and contributes to silent grant on subsequent requests.
	// By marking response as ephemeral, OP skips persistence.
	Ephemeral bool `json:"ephemeral"`
}

// AccessToken is the inflated representation of an access token.
type AccessToken struct {
	Value          string
	Type           string
	ExpiresIn      int64
	ClientId       string
	Scopes         []string
	UserInfoClaims map[string]interface{}
}

// AccessTokenClaims is the payload of a JWT encoded AccessToken issued by Tiga.
type AccessTokenClaims struct {
	jwt.Claims
	Client   string                 `json:"client"`
	Scope    string                 `json:"scope"`
	UserInfo map[string]interface{} `json:"userinfo,omitempty"`
}

func (c *AccessTokenClaims) Get(name string) (interface{}, bool) {
	switch name {
	case jwx.ClaimJti:
		return c.ID, true
	case jwx.ClaimSub:
		return c.Subject, true
	case jwx.ClaimAud:
		return []string(c.Audience), true
	case jwx.ClaimExp:
		return c.Expiry.Time(), true
	case jwx.ClaimNbf:
		return c.NotBefore.Time(), true
	case jwx.ClaimIat:
		return c.IssuedAt.Time(), true
	case jwx.ClaimIss:
		return c.Issuer, true
	case "client":
		return c.Client, true
	case "scope":
		return c.Scope, true
	case "userinfo":
		return c.UserInfo, true
	default:
		return nil, false
	}
}

// TokenResponse is the response object at token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    *int64 `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ErrorResponse is the response object when error has occurred at token endpoint.
type ErrorResponse struct {
	Status int    `json:"status"`
	Code   string `json:"error,omitempty"`
	Reason string `json:"error_description,omitempty"`
}

func (r *ErrorResponse) Error() string {
	return fmt.Sprintf("[%d]%s: %s", r.Status, r.Code, r.Reason)
}
