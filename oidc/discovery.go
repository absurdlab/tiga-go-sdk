package oidc

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
	return []string{"todo"}
}
