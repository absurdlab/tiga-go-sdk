package oidc

import (
	"encoding/json"
	"github.com/absurdlab/tiga-go-sdk/internal"
	"io"
	"time"
)

// ReadDiscovery reads a Discovery from io.Reader.
func ReadDiscovery(reader io.Reader) (*Discovery, error) {
	var d Discovery
	if err := json.NewDecoder(reader).Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

// Discovery is the specification defined OpenID Connect configuration metadata plus custom extensions
type Discovery struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserInfoEndpoint                           string   `json:"userinfo_endpoint"`
	JSONWebKeySetURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint                       string   `json:"registration_endpoint"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	AcrValuesSupported                         []string `json:"acr_values_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	IdTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported"`
	IdTokenEncryptionEncValuesSupported        []string `json:"id_token_encryption_enc_values_supported"`
	UserInfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported"`
	UserInfoEncryptionAlgValuesSupported       []string `json:"userinfo_encryption_alg_values_supported"`
	UserInfoEncryptionEncValuesSupported       []string `json:"userinfo_encryption_enc_values_supported"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported"`
	RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported"`
	RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	DisplayValuesSupported                     []string `json:"display_values_supported"`
	ClaimTypesSupported                        []string `json:"claim_types_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ServiceDocumentation                       string   `json:"service_documentation"`
	UILocalesSupported                         []string `json:"ui_locales_supported"`
	ClaimsParameterSupported                   *bool    `json:"claims_parameter_supported"`
	RequestParameterSupported                  *bool    `json:"request_parameter_supported"`
	RequestURIParameterSupported               *bool    `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration              *bool    `json:"require_request_uri_registration"`
	OPPolicyURI                                string   `json:"op_policy_uri"`
	OPTermsOfServiceURI                        string   `json:"op_tos_uri"`

	// AuthorizeResumeEndpoint is the endpoint where OP can resume processing of the
	// original authorize request. This HTTP GET endpoint accepts a single "challenge"
	// parameter which is capable to restoring authorize request and session. Interaction
	// providers should send End-User to this endpoint after completing interaction with
	// LoginEndpoint, SelectAccountEndpoint, or ConsentEndpoint.
	AuthorizeResumeEndpoint string `json:"authorize_resume_endpoint"`

	// LoginEndpoint is the endpoint where OP interacts with login providers.
	// OP will expose two endpoints here. With HTTP GET method and a challenge
	// parameter, the provider can retrieve interaction state. With HTTP POST
	// method and a challenge parameter, the provider can post login result.
	LoginEndpoint string `json:"login_endpoint"`

	// SelectAccountEndpoint is the endpoint where OP interacts with the select account
	// providers. OP will expose two endpoints here. With HTTP GET method and a challenge
	// parameter, the provider can retrieve interaction state. With HTTP POST method and a
	// challenge parameter, the provider can post account selection result.
	SelectAccountEndpoint string `json:"select_account_endpoint"`

	// ConsentEndpoint is the endpoint where OP interacts with the consent providers.
	// OP will expose two endpoints here. With HTTP GET method and a challenge parameter,
	// the provider can retrieve interaction state. With HTTP POST method and a challenge
	// parameter, the provider can post consent result.
	ConsentEndpoint string `json:"consent_endpoint"`

	// CodeLifespan is the number of seconds that the newly issued authorization code
	// will be valid for.
	CodeLifespan int64 `json:"code_lifespan"`

	// AccessTokenLifespan is the number of seconds that the newly issued access token
	// will be valid for.
	AccessTokenLifespan int64 `json:"access_token_lifespan"`

	// RefreshTokenLifespan is the number of seconds that the newly issued refresh token
	// will be valid for.
	RefreshTokenLifespan int64 `json:"refresh_token_lifespan"`

	// IdTokenLifespan is the number of seconds that the newly issued id token will be
	// valid for.
	IdTokenLifespan int64 `json:"id_token_lifespan"`

	// CodeSigningAlgValue is the value of the signing algorithm used to sign the
	// authorization code.
	CodeSigningAlgValue string `json:"code_signing_alg_value"`

	// AccessTokenSigningAlgValue is the value of the signing algorithm used to sign
	// the access token.
	AccessTokenSigningAlgValue string `json:"access_token_signing_alg_value"`

	// InteractionContextDataKBLimit is the size limit in kilobytes that the context data
	// of the interaction callback is limited to. If the context data exceeds this size
	// limit, it will no longer be accepted by Tiga.
	InteractionContextDataKBLimit int64 `json:"interaction_context_data_kb_limit"`
}

// ResponseModesSupportedOrDefault returns Discovery#ResponseModesSupported if it is not
// empty, or ["query", "fragment"] if it is empty.
//
//	response_modes_supported:
//	If omitted, the default for Dynamic OpenID Providers is ["query", "fragment"].
//
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
func (d *Discovery) ResponseModesSupportedOrDefault() []string {
	if len(d.ResponseModesSupported) > 0 {
		return d.ResponseModesSupported
	}
	return []string{ResponseModeQuery, ResponseModeFragment}
}

// GrantTypesSupportedOrDefault returns Discovery#GrantTypesSupported if it is not
// empty, or ["authorization_code", "implicit"] if it is empty.
//
//	grant_types_supported:
// 	Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type
//	values and MAY support other Grant Types. If omitted, the default value is
//	["authorization_code", "implicit"].
//
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
func (d *Discovery) GrantTypesSupportedOrDefault() []string {
	if len(d.GrantTypesSupported) > 0 {
		return d.GrantTypesSupported
	}
	return []string{GrantTypeAuthorizationCode, GrantTypeImplicit}
}

// TokenEndpointAuthMethodsSupportedOrDefault returns Discovery#TokenEndpointAuthMethodsSupported if it
// is not empty, or ["client_secret_basic"] if it is empty.
//
//	token_endpoint_auth_methods_supported:
//	If omitted, the default is client_secret_basic -- the HTTP Basic Authentication Scheme specified
//	in Section 2.3.1 of OAuth 2.0 [RFC6749].
//
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
func (d *Discovery) TokenEndpointAuthMethodsSupportedOrDefault() []string {
	if len(d.TokenEndpointAuthMethodsSupported) > 0 {
		return d.TokenEndpointAuthMethodsSupported
	}
	return []string{ClientSecretBasic}
}

// ClaimTypesSupportedOrDefault returns Discovery#ClaimTypesSupported if it is not empty, or ["normal"] if it is empty.
//
//	claim_types_supported:
// 	If omitted, the implementation supports only normal Claims.
//
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
func (d *Discovery) ClaimTypesSupportedOrDefault() []string {
	if len(d.ClaimTypesSupported) > 0 {
		return d.ClaimTypesSupported
	}
	return []string{ClaimTypeNormal}
}

// ClaimsParameterSupportedOrDefault returns Discovery#ClaimsParameterSupported or false.
//
//	claims_parameter_supported:
//	If omitted, the default value is false.
//
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
func (d *Discovery) ClaimsParameterSupportedOrDefault() bool {
	if d.ClaimsParameterSupported != nil {
		return *d.ClaimsParameterSupported
	}
	return false
}

// RequestParameterSupportedOrDefault returns Discovery#RequestParameterSupported or false
//
// 	request_parameter_supported:
//	If omitted, the default value is false.
//
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
func (d *Discovery) RequestParameterSupportedOrDefault() bool {
	if d.RequestParameterSupported != nil {
		return *d.RequestParameterSupported
	}
	return false
}

// RequestURIParameterSupportedOrDefault returns Discovery#RequestURIParameterSupported or true
//
// 	request_uri_parameter_supported:
//	If omitted, the default value is true.
//
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
func (d *Discovery) RequestURIParameterSupportedOrDefault() bool {
	if d.RequestURIParameterSupported != nil {
		return *d.RequestURIParameterSupported
	}
	return true
}

// RequireRequestURIRegistrationOrDefault returns Discovery#RequireRequestURIRegistration or false
//
// 	require_request_uri_registration:
//	If omitted, the default value is false.
//
// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
func (d *Discovery) RequireRequestURIRegistrationOrDefault() bool {
	if d.RequireRequestURIRegistration != nil {
		return *d.RequireRequestURIRegistration
	}
	return false
}

// CodeLifespanDuration returns the time.Duration of CodeLifespan.
func (d *Discovery) CodeLifespanDuration() time.Duration {
	return time.Duration(d.CodeLifespan) * time.Second
}

// AccessTokenLifespanDuration returns the time.Duration of AccessTokenLifespan
func (d *Discovery) AccessTokenLifespanDuration() time.Duration {
	return time.Duration(d.AccessTokenLifespan) * time.Second
}

// RefreshTokenLifespanDuration returns the time.Duration of RefreshTokenLifespan.
func (d *Discovery) RefreshTokenLifespanDuration() time.Duration {
	return time.Duration(d.RefreshTokenLifespan) * time.Second
}

// IdTokenLifespanDuration returns the time.Duration of IdTokenLifespan.
func (d *Discovery) IdTokenLifespanDuration() time.Duration {
	return time.Duration(d.IdTokenLifespan) * time.Second
}

// Clone returns a new Discovery object with the same parameters.
func (d *Discovery) Clone() *Discovery {
	return &Discovery{
		Issuer:                                     d.Issuer,
		AuthorizationEndpoint:                      d.AuthorizationEndpoint,
		TokenEndpoint:                              d.TokenEndpoint,
		UserInfoEndpoint:                           d.UserInfoEndpoint,
		JSONWebKeySetURI:                           d.JSONWebKeySetURI,
		RegistrationEndpoint:                       d.RegistrationEndpoint,
		ScopesSupported:                            internal.CopyArray(d.ScopesSupported),
		ResponseTypesSupported:                     internal.CopyArray(d.ResponseTypesSupported),
		ResponseModesSupported:                     internal.CopyArray(d.ResponseModesSupported),
		GrantTypesSupported:                        internal.CopyArray(d.GrantTypesSupported),
		AcrValuesSupported:                         internal.CopyArray(d.AcrValuesSupported),
		SubjectTypesSupported:                      internal.CopyArray(d.SubjectTypesSupported),
		IdTokenSigningAlgValuesSupported:           internal.CopyArray(d.IdTokenSigningAlgValuesSupported),
		IdTokenEncryptionAlgValuesSupported:        internal.CopyArray(d.IdTokenEncryptionAlgValuesSupported),
		IdTokenEncryptionEncValuesSupported:        internal.CopyArray(d.IdTokenEncryptionEncValuesSupported),
		UserInfoSigningAlgValuesSupported:          internal.CopyArray(d.UserInfoSigningAlgValuesSupported),
		UserInfoEncryptionAlgValuesSupported:       internal.CopyArray(d.UserInfoEncryptionAlgValuesSupported),
		UserInfoEncryptionEncValuesSupported:       internal.CopyArray(d.UserInfoEncryptionEncValuesSupported),
		RequestObjectSigningAlgValuesSupported:     internal.CopyArray(d.RequestObjectSigningAlgValuesSupported),
		RequestObjectEncryptionAlgValuesSupported:  internal.CopyArray(d.RequestObjectEncryptionAlgValuesSupported),
		RequestObjectEncryptionEncValuesSupported:  internal.CopyArray(d.RequestObjectEncryptionEncValuesSupported),
		TokenEndpointAuthMethodsSupported:          internal.CopyArray(d.TokenEndpointAuthMethodsSupported),
		TokenEndpointAuthSigningAlgValuesSupported: internal.CopyArray(d.TokenEndpointAuthSigningAlgValuesSupported),
		DisplayValuesSupported:                     internal.CopyArray(d.DisplayValuesSupported),
		ClaimTypesSupported:                        internal.CopyArray(d.ClaimTypesSupported),
		ClaimsSupported:                            internal.CopyArray(d.ClaimsSupported),
		ServiceDocumentation:                       d.ServiceDocumentation,
		UILocalesSupported:                         internal.CopyArray(d.UILocalesSupported),
		ClaimsParameterSupported:                   internal.CopyBool(d.ClaimsParameterSupported),
		RequestParameterSupported:                  internal.CopyBool(d.RequestParameterSupported),
		RequestURIParameterSupported:               internal.CopyBool(d.RequestURIParameterSupported),
		RequireRequestURIRegistration:              internal.CopyBool(d.RequireRequestURIRegistration),
		OPPolicyURI:                                d.OPPolicyURI,
		OPTermsOfServiceURI:                        d.OPTermsOfServiceURI,
		AuthorizeResumeEndpoint:                    d.AuthorizeResumeEndpoint,
		LoginEndpoint:                              d.LoginEndpoint,
		SelectAccountEndpoint:                      d.SelectAccountEndpoint,
		ConsentEndpoint:                            d.ConsentEndpoint,
		CodeLifespan:                               d.CodeLifespan,
		AccessTokenLifespan:                        d.AccessTokenLifespan,
		RefreshTokenLifespan:                       d.RefreshTokenLifespan,
		IdTokenLifespan:                            d.IdTokenLifespan,
		CodeSigningAlgValue:                        d.CodeSigningAlgValue,
		AccessTokenSigningAlgValue:                 d.AccessTokenSigningAlgValue,
	}
}
