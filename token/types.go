package token

import (
	"fmt"
	"github.com/absurdlab/tiga-go-sdk/jwx"
	"gopkg.in/square/go-jose.v2/jwt"
)

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
type Response struct {
	AccessToken  string `json:"access_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresIn    *int64 `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IdToken      string `json:"id_token,omitempty"`
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
