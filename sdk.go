package tigasdk

import (
	"context"
	"crypto/tls"
	"github.com/absurdlab/tiga-go-sdk/internal"
	"github.com/absurdlab/tiga-go-sdk/jwx"
	"github.com/absurdlab/tiga-go-sdk/oidc"
	"github.com/imulab/coldcall"
	"github.com/imulab/coldcall/body"
	"github.com/imulab/coldcall/status"
	"net/http"
	"strings"
	"time"
)

const DefaultServiceBaseURL = "https://sso.elan-vision.com"

// Option describes logic to configure the SDK
type Option func(sdk *SDK)

var (
	// DefaultHTTPClient is the default http.Client used by the SDK if none is set. It uses a 10 second
	// timeout setting, does not follow redirects and skip TLS verification.
	DefaultHTTPClient = &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	// WithServiceBaseURL sets the base Tiga url used by the sdk. By default,
	// DefaultServiceBaseURL is used.
	WithServiceBaseURL = func(url string) Option {
		return func(sdk *SDK) {
			sdk.serviceBaseURL = strings.TrimSuffix(url, "/")
		}
	}

	// WithClientSecretBasic sets the client id and client secret on the sdk object. The sdk will
	// use client_secret_basic method when requesting token endpoint.
	WithClientSecretBasic = func(clientId string, clientSecret string) Option {
		return func(sdk *SDK) {
			sdk.clientId = clientId
			sdk.clientSecret = clientSecret
			sdk.authMethod = oidc.ClientSecretBasic
		}
	}

	// WithClientSecretPost sets the client id and client secret on the sdk object. The sdk will
	// use client_secret_post method when requesting token endpoint.
	WithClientSecretPost = func(clientId string, clientSecret string) Option {
		return func(sdk *SDK) {
			sdk.clientId = clientId
			sdk.clientSecret = clientSecret
			sdk.authMethod = oidc.ClientSecretPost
		}
	}

	// WithPrivateKeyJwt sets the client id, client jwks and the signature algorithm to use
	// to sign the client_assertion parameter. The sdk will use private_key_jwt method when
	// requesting token endpoint.
	WithPrivateKeyJwt = func(clientId string, clientJwks *jwx.KeySet, signingAlg string) Option {
		return func(sdk *SDK) {
			sdk.clientId = clientId
			sdk.clientJwks = clientJwks
			sdk.authSigAlg = signingAlg
		}
	}

	// WithClientJwks sets the client jwks for the sdk.
	WithClientJwks = func(clientJwks *jwx.KeySet) Option {
		return func(sdk *SDK) {
			sdk.clientJwks = clientJwks
		}
	}

	// WithHTTPClient set the http client used by the sdk to make http request.
	// By default, if nothing is set, the sdk uses a default http client with
	// 10 second timeout and skips tls verification.
	WithHTTPClient = func(httpClient *http.Client) Option {
		return func(sdk *SDK) {
			sdk.httpClient = httpClient
		}
	}
)

// New creates a new sdk object to expose various features. A series of Option can be applied to customize its parameters.
func New(options ...Option) *SDK {
	sdk := new(SDK)
	for _, opt := range options {
		opt(sdk)
	}

	if sdk.httpClient == nil {
		sdk.httpClient = DefaultHTTPClient
	}

	sdk.serviceBaseURL = internal.Coalesce(sdk.serviceBaseURL, DefaultServiceBaseURL)

	sdk.mustGetDiscovery()
	sdk.mustGetTigaJwks()

	return sdk
}

// SDK is the entrypoint of the kit.
type SDK struct {
	clientId       string
	clientSecret   string
	clientJwks     *jwx.KeySet
	authMethod     string
	authSigAlg     string
	serviceBaseURL string
	discovery      *oidc.Discovery
	tigaJwks       *jwx.KeySet
	httpClient     *http.Client
}

func (s *SDK) mustGetDiscovery() {
	req, err := coldcall.Get(context.Background(), s.serviceBaseURL+"/.well-known/openid-configuration")
	if err != nil {
		panic(err)
	}

	var newDiscovery coldcall.Constructor = func() interface{} {
		return new(oidc.Discovery)
	}

	d, _, err := coldcall.Response(s.httpClient.Do(req)).
		Expect(status.Is200, body.JSONUnmarshal(newDiscovery)).
		Read()
	if err != nil {
		panic(err)
	}

	s.discovery = d.(*oidc.Discovery)
}

func (s *SDK) mustGetTigaJwks() {
	req, err := coldcall.Get(context.Background(), s.serviceBaseURL+"/.well-known/jwks.json")
	if err != nil {
		panic(err)
	}

	var newJwks coldcall.Constructor = func() interface{} {
		return jwx.NewKeySet()
	}

	set, _, err := coldcall.Response(s.httpClient.Do(req)).
		Expect(status.Is200, body.JSONUnmarshal(newJwks)).
		Read()
	if err != nil {
		panic(err)
	}

	s.tigaJwks = set.(*jwx.KeySet)
}
