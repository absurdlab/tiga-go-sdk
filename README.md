# Tiga SDK for Golang

![Default](https://github.com/absurdlab/tiga-go-sdk/workflows/Default/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/absurdlab/tiga-go-sdk)](https://goreportcard.com/report/github.com/absurdlab/tiga-go-sdk)
[![Version](https://img.shields.io/badge/version-0.1.0-blue)](https://img.shields.io/badge/version-0.1.0-blue)

Golang SDK for the Tiga OIDC engine

## Install

```bash
go get -u github.com/absurdlab/tiga-go-sdk
```

The SDK relies on:
1. [github.com/imulab/coldcall](https://github.com/imulab/coldcall) to make HTTP calls
2. [gopkg.in/square/go-jose.v2](https://github.com/square/go-jose) to handle cryptography.

## Get started

The main entrypoint of the SDK is the `SDK` object. To create it:

```go
import (
    tigasdk "github.com/absurdlab/tiga-go-sdk"
)

var sdk = tigasdk.New(
    tigasdk.WithClientSecretBasic("example_client", "example_secret"),
)
```

### HTTP Middleware

It is very easy to create an HTTP Middleware (i.e. `func(http.Handler) http.Handler`) to protect your endpoints.

```go
httpMiddleware := sdk.Protect(tigasdk.ProtectOpt{
    Scopes: []string{"my_required_scope"},
    Leeway: 5 * time.Second,
})
```

### Token endpoints

To execute the various token endpoint flows:

```go
// client credentials flow
sdk.TokenByClientCredentials(ctx, []string{"my_scope"})

// authorization code flow (token endpoint leg)
sdk.TokenByCode(ctx, "auth_code", "https://redirect_uri", []string{"granted_scope"})

// exchange refresh token
sdk.TokenByRefreshToken(ctx, "refresh_token", []string{"granted_scope"})
```

### Interaction providers

The SDK makes it easy for interaction providers (a special Tiga client) to interact with Tiga.

```go
challenge := "challenge_parameter_from_url"

// Get state for login challenge
state, _ := sdk.LoginState(ctx, challenge)
// Post provider login response back to Tiga
sdk.LoginCallback(ctx, challenge, &tigasdk.LoginCallback{...})

// Get state for select account challenge
state, _ := sdk.SelectAccountState(ctx, challenge)
// Post provider select account response back to Tiga
sdk.SelectAccountCallback(ctx, challenge, &tigasdk.SelectAccountCallback{...})

// Get state for consent challenge
state, _ := sdk.ConsentState(ctx, challenge)
// Post provider consent response back to Tiga
sdk.ConsentCallback(ctx, challenge, &tigasdk.ConsentCallback{...})

// Render HTTP response to redirect browser back to Tiga at any point.
sdk.ResumeAuthorize(httpResponseWriter, httpRequest, challenge)
```