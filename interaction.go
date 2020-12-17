package tigasdk

import (
	"context"
	"errors"
	"fmt"
	"github.com/absurdlab/tiga-go-sdk/oidc"
	"github.com/imulab/coldcall"
	"github.com/imulab/coldcall/addr"
	"github.com/imulab/coldcall/body"
	"github.com/imulab/coldcall/header"
	"github.com/imulab/coldcall/status"
	"net/http"
	"net/url"
)

var (
	ErrContextTooLarge = errors.New("context data exceeds discovery limit")
)

// LoginState gets the InteractionState of the login challenge.
func (s *SDK) LoginState(ctx context.Context, challenge string) (*InteractionState, error) {
	return s.getInteractionState(ctx, s.discovery.LoginEndpoint, challenge, []string{oidc.ScopeTigaLogin})
}

// SelectAccountState gets the InteractionState of the select account challenge.
func (s *SDK) SelectAccountState(ctx context.Context, challenge string) (*InteractionState, error) {
	return s.getInteractionState(ctx, s.discovery.SelectAccountEndpoint, challenge, []string{oidc.ScopeTigaSelectAccount})
}

// ConsentState gets the InteractionState of the consent challenge.
func (s *SDK) ConsentState(ctx context.Context, challenge string) (*InteractionState, error) {
	return s.getInteractionState(ctx, s.discovery.ConsentEndpoint, challenge, []string{oidc.ScopeTigaConsent})
}

// LoginCallback posts the End-User's LoginCallback response back to Tiga.
func (s *SDK) LoginCallback(ctx context.Context, challenge string, callback *LoginCallback) (bool, error) {
	if limit := s.discovery.InteractionContextDataKBLimit; limit > 0 && int64(len(callback.Context))/1024 > limit {
		return false, ErrContextTooLarge
	}
	return s.interactionCallback(ctx, s.discovery.LoginEndpoint, challenge, []string{oidc.ScopeTigaLogin}, callback)
}

// SelectAccountCallback posts the End-User's SelectAccountCallback response back to Tiga.
func (s *SDK) SelectAccountCallback(ctx context.Context, challenge string, callback *SelectAccountCallback) (bool, error) {
	return s.interactionCallback(ctx, s.discovery.SelectAccountEndpoint, challenge, []string{oidc.ScopeTigaSelectAccount}, callback)
}

// ConsentCallback posts the End-User's ConsentCallback response back to Tiga.
func (s *SDK) ConsentCallback(ctx context.Context, challenge string, callback *ConsentCallback) (bool, error) {
	return s.interactionCallback(ctx, s.discovery.ConsentEndpoint, challenge, []string{oidc.ScopeTigaConsent}, callback)
}

func (s *SDK) interactionCallback(ctx context.Context, endpoint string, challenge string, scopes []string, callback interface{}) (bool, error) {
	tr, err := s.TokenByClientCredentials(ctx, scopes)
	if err != nil {
		return false, err
	}

	req, err := coldcall.Post(ctx, endpoint,
		addr.WithQueryMap(map[string]string{"challenge": challenge}),
		header.ContentType(header.ContentTypeApplicationJSON),
		header.Custom("Authorization", fmt.Sprintf("%s %s", tr.TokenType, tr.AccessToken)),
		body.JSONMarshal(callback),
	)
	if err != nil {
		return false, err
	}

	var (
		successProducer    coldcall.Producer    = func(_ []byte) (interface{}, error) { return true, nil }
		failureConstructor coldcall.Constructor = func() interface{} { return new(ErrorResponse) }
	)

	_, _, err = coldcall.Response(s.httpClient.Do(req)).
		Expect(status.Is(http.StatusNoContent), successProducer).
		Expect(status.IsFailure, body.JSONUnmarshal(failureConstructor)).
		Read()
	if err != nil {
		return false, err
	}

	return true, nil
}

func (s *SDK) getInteractionState(ctx context.Context, endpoint string, challenge string, scopes []string) (*InteractionState, error) {
	tr, err := s.TokenByClientCredentials(ctx, scopes)
	if err != nil {
		return nil, err
	}

	req, err := coldcall.Get(ctx, endpoint,
		addr.WithQueryMap(map[string]string{"challenge": challenge}),
		header.Custom("Authorization", fmt.Sprintf("%s %s", tr.TokenType, tr.AccessToken)),
	)
	if err != nil {
		return nil, err
	}

	var (
		successConstructor coldcall.Constructor = func() interface{} { return new(InteractionState) }
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
	case *InteractionState:
		return result.(*InteractionState), nil
	case *ErrorResponse:
		return nil, result.(*ErrorResponse)
	default:
		return nil, ErrUnexpectedResponse
	}
}

// ResumeAuthorize redirects the http response back to the authorize resume endpoint.
func (s *SDK) ResumeAuthorize(rw http.ResponseWriter, r *http.Request, challenge string) {
	u, _ := url.Parse(s.discovery.AuthorizeResumeEndpoint)
	u.RawQuery = url.Values{"challenge": []string{challenge}}.Encode()
	http.Redirect(rw, r, u.String(), http.StatusFound)
}
