package tigasdk

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/absurdlab/tiga-go-sdk/jwx"
	"github.com/absurdlab/tiga-go-sdk/oidc"
	"github.com/imulab/coldcall"
	"github.com/imulab/coldcall/body"
	"github.com/imulab/coldcall/header"
	"github.com/imulab/coldcall/status"
	"gopkg.in/square/go-jose.v2/jwt"
	"strings"
	"time"
)

var (
	ErrUnexpectedResponse = errors.New("sdk received unexpected response")
)

func (s *SDK) TokenByClientCredentials(ctx context.Context, scopes []string) (*TokenResponse, error) {
	options, err := s.createTokenRequest(map[string]string{
		"client_id":  s.clientId,
		"grant_type": oidc.GrantTypeClientCredentials,
		"scope":      strings.Join(scopes, " "),
	})
	if err != nil {
		return nil, err
	}

	return s.executeTokenRequest(ctx, options)
}

func (s *SDK) TokenByCode(ctx context.Context, code string, redirectURI string, scopes []string) (*TokenResponse, error) {
	options, err := s.createTokenRequest(map[string]string{
		"client_id":    s.clientId,
		"redirect_uri": redirectURI,
		"grant_type":   oidc.GrantTypeAuthorizationCode,
		"scope":        strings.Join(scopes, " "),
		"code":         code,
	})
	if err != nil {
		return nil, err
	}

	return s.executeTokenRequest(ctx, options)
}

func (s *SDK) TokenByRefreshToken(ctx context.Context, refreshToken string, scopes []string) (*TokenResponse, error) {
	options, err := s.createTokenRequest(map[string]string{
		"client_id":     s.clientId,
		"grant_type":    oidc.GrantTypeRefreshToken,
		"scope":         strings.Join(scopes, " "),
		"refresh_token": refreshToken,
	})
	if err != nil {
		return nil, err
	}

	return s.executeTokenRequest(ctx, options)
}

func (s *SDK) createTokenRequest(initial map[string]string) ([]coldcall.Option, error) {
	var options []coldcall.Option

	switch s.authMethod {
	case oidc.ClientSecretBasic:
		options = append(options, header.Custom(
			"Authorization",
			base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", s.clientId, s.clientSecret)))),
		)
	case oidc.ClientSecretPost:
		initial["client_secret"] = s.clientSecret
	case oidc.PrivateKeyJwt:
		initial["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
		if assertion, err := jwx.EncodeToString(jwx.SignatureKeyByAlg(s.authSigAlg, s.clientJwks), jwx.SkipKeySource, jwt.Claims{
			Issuer:    s.clientId,
			Subject:   s.clientId,
			Audience:  []string{s.discovery.TokenEndpoint},
			Expiry:    jwt.NewNumericDate(time.Now().Add(10 * time.Second)),
			NotBefore: jwt.NewNumericDate(time.Now()),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		}); err != nil {
			return nil, err
		} else {
			initial["client_assertion"] = assertion
		}
	default:
		panic("impossible auth method")
	}

	options = append(options, header.ContentType(header.ContentTypeApplicationFormUrlEncoded))
	options = append(options, body.URLValuesMapEncode(initial))

	return options, nil
}

func (s *SDK) executeTokenRequest(ctx context.Context, options []coldcall.Option) (*TokenResponse, error) {
	req, err := coldcall.Post(ctx, s.discovery.TokenEndpoint, options...)
	if err != nil {
		return nil, err
	}

	var (
		successConstructor coldcall.Constructor = func() interface{} { return new(TokenResponse) }
		failureConstructor coldcall.Constructor = func() interface{} { return new(ErrorResponse) }
	)

	result, _, err := coldcall.Response(s.httpClient.Do(req)).
		Expect(status.Is200, body.JSONUnmarshal(successConstructor)).
		Expect(status.IsFailure, body.JSONUnmarshal(failureConstructor)).
		Read()
	if err != nil {
		return nil, err
	}

	switch result.(type) {
	case *TokenResponse:
		return result.(*TokenResponse), nil
	case *ErrorResponse:
		return nil, result.(*ErrorResponse)
	default:
		return nil, ErrUnexpectedResponse
	}
}
