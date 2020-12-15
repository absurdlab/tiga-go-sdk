package tigasdk

import (
	"context"
	"errors"
	"github.com/absurdlab/tiga-go-sdk/internal"
	"github.com/absurdlab/tiga-go-sdk/jwx"
	"net/http"
	"strings"
	"time"
)

const AccessTokenType = "Bearer"

var (
	ErrAccessTokenNotSet   = errors.New("access token not set on context")
	ErrMalformedAuthHeader = errors.New("authorization header is malformed")
	ErrInvalidAccessToken  = errors.New("access token is invalid")
	ErrInsufficientScope   = errors.New("insufficient scope")
)

// ProtectOpt is the options for Protect middleware.
type ProtectOpt struct {
	// Audience is the expected "aud" in the access token claims.
	// When empty or nil, "aud" validation is not performed.
	Audience []string

	// Subject is the expected "sub" in the access token claims.
	// When empty or nil, "sub" validation is not performed.
	Subject string

	// Scopes is the list of required scopes in the access token claims.
	// When empty or nil, "scope" validation is not performed.
	Scopes []string

	// Leeway is the time skew tolerance
	Leeway time.Duration

	// RenderError is the function that is called in case of error. If not
	// provided, the middleware just write 401 status.
	RenderError func(http.ResponseWriter, *http.Request, error)
}

// Protect returns a HTTP middleware to require access token issued by Tiga service in order to access the resource.
func (s *SDK) Protect(opt *ProtectOpt) func(http.Handler) http.Handler {
	if opt == nil {
		opt = &ProtectOpt{}
	}

	if opt.RenderError == nil {
		opt.RenderError = func(rw http.ResponseWriter, r *http.Request, err error) {
			rw.WriteHeader(http.StatusUnauthorized)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if len(header) == 0 || !strings.HasPrefix(header, AccessTokenType+" ") {
				opt.RenderError(rw, r, ErrMalformedAuthHeader)
				return
			}

			rawToken := strings.TrimPrefix(header, AccessTokenType+" ")

			var claims = new(AccessTokenClaims)
			if err := jwx.Decode(
				rawToken,
				s.tigaJwks, nil,
				jwx.Algs{Sig: "?"}, // use '?' to trick IsNone, entirely depend on JWS header values
				claims,
			); err != nil {
				opt.RenderError(rw, r, ErrInvalidAccessToken)
				return
			}

			var rules []jwx.Expect
			{
				rules = append(rules, jwx.ExpectIss(s.discovery.Issuer))
				rules = append(rules, jwx.ExpectTime(opt.Leeway))
				if len(opt.Audience) > 0 {
					rules = append(rules, jwx.ExpectAud(opt.Audience...))
				}
				if len(opt.Subject) > 0 {
					rules = append(rules, jwx.ExpectSub(opt.Subject))
				}
				if len(opt.Scopes) > 0 {
					rules = append(rules, func(c jwx.Claims) error {
						v, ok := c.Get("scope")
						if ok {
							if scope, ok := v.(string); ok {
								granted := internal.NewSet(strings.Fields(scope)...)
								required := internal.NewSet(opt.Scopes...)
								if granted.ContainsAll(required) {
									return nil
								}
							}
						}
						return ErrInsufficientScope
					})
				}
			}
			if err := jwx.ValidateClaims(claims, rules...); err != nil {
				opt.RenderError(rw, r, err)
				return
			}

			ctx := context.WithValue(r.Context(), accessTokenContextKey{}, &AccessToken{
				Value:          rawToken,
				Type:           AccessTokenType,
				ExpiresIn:      int64(claims.Expiry.Time().Sub(time.Now()) / time.Second),
				ClientId:       claims.Client,
				Scopes:         strings.Fields(claims.Scope),
				UserInfoClaims: claims.UserInfo,
			})

			next.ServeHTTP(rw, r.WithContext(ctx))
		})
	}
}

type accessTokenContextKey struct{}

// GetAccessToken retrieves the grant.AccessToken from the context. If no token was set on context, or the object
// set on context was not grant.AccessToken, ErrAccessTokenNotSet is returned as error.
func GetAccessToken(ctx context.Context) (*AccessToken, error) {
	v := ctx.Value(accessTokenContextKey{})
	if v == nil {
		return nil, ErrAccessTokenNotSet
	}

	tok, ok := v.(*AccessToken)
	if !ok {
		return nil, ErrAccessTokenNotSet
	}

	return tok, nil
}
