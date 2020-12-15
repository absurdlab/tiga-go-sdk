package jwx

import (
	"encoding/json"
	"errors"
	"github.com/absurdlab/tiga-go-sdk/internal"
	"time"
)

// Standard claim names
const (
	ClaimJti = "jti"
	ClaimSub = "sub"
	ClaimAud = "aud"
	ClaimExp = "exp"
	ClaimNbf = "nbf"
	ClaimIat = "iat"
)

var (
	ErrAbsentJti   = errors.New("jti claim is absent")
	ErrInvalidSub  = errors.New("sub claim is invalid")
	ErrInvalidAud  = errors.New("aud claim is invalid")
	ErrExpExpired  = errors.New("exp claim is invalid because token has expired")
	ErrIatInFuture = errors.New("iat claim is invalid because token is issued in future")
	ErrNbfTooSoon  = errors.New("nbf claim is invalid because token is used too soon")
)

// Claims is JWT claims.
type Claims interface {
	// Get returns the top level claim by its name. For standard claim names, Get needs
	// to return compatible values as follows:
	//
	//	jti: string
	//	sub: string
	//	aud: []string, or nil
	//	exp: time.Time
	//	nbf: time.Time
	//	iat: time.Time
	//
	// The above compatible return values will ensure Claims work well with ValidateClaims and
	// the out-of-box Expect rules.
	Get(name string) (interface{}, bool)
}

// NewMapClaims returns a new map based implementation of Claims. This implementation store all
// claims in a generic map, which is necessary when dynamic claims are expected.
func NewMapClaims(claims map[string]interface{}) Claims {
	return &mapClaims{m: claims}
}

type mapClaims struct {
	m map[string]interface{}
}

func (c *mapClaims) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.m)
}

func (c *mapClaims) UnmarshalJSON(bytes []byte) error {
	c.m = make(map[string]interface{})
	return json.Unmarshal(bytes, &c.m)
}

func (c mapClaims) Get(name string) (interface{}, bool) {
	v, ok := c.m[name]
	if v != nil {
		switch name {
		case ClaimJti, ClaimSub:
			switch v.(type) {
			case string:
				return v, true
			default:
				return nil, false
			}
		case ClaimAud:
			switch v.(type) {
			case string:
				return []string{v.(string)}, true
			case []string:
				return v, true
			default:
				return nil, false
			}
		case ClaimExp, ClaimNbf, ClaimIat:
			switch v.(type) {
			case int64:
				return time.Unix(v.(int64), 0), true
			case int:
				return time.Unix(int64(v.(int)), 0), true
			default:
				return nil, false
			}
		}
	}
	return v, ok
}

// ValidateClaims runs the Claims against a series of Expect rules. Any error is returned immediately.
func ValidateClaims(c Claims, expectations ...Expect) error {
	for _, each := range expectations {
		if err := each(c); err != nil {
			return err
		}
	}
	return nil
}

// Expect expects a Claims to conform to certain characteristics.
type Expect func(c Claims) error

var (
	// ExpectJti expects the "jti" claim is present and non-empty. If "jti"
	// is not present, ErrAbsentJti is returned.
	ExpectJti Expect = func(c Claims) error {
		if v, ok := c.Get(ClaimJti); ok {
			if jti, ok := v.(string); ok && len(jti) > 0 {
				return nil
			}
		}
		return ErrAbsentJti
	}
	// ExpectSub returns an Expect rule to check if the subject is present
	// and is one of the expected subject values. If "sub" is not present, or
	// is not one of the legal values, ErrInvalidSub is returned.
	ExpectSub = func(subjects ...string) Expect {
		return func(c Claims) error {
			if v, ok := c.Get(ClaimSub); ok {
				if sub, ok := v.(string); ok {
					for _, each := range subjects {
						if each == sub {
							return nil
						}
					}
				}
			}
			return ErrInvalidSub
		}
	}
	// ExpectAud returns an Expect rule to check if the audience is present and that
	// one of the audience values is among the expected audiences. If condition is not
	// met, ErrInvalidAud is returned.
	ExpectAud = func(audiences ...string) Expect {
		expected := internal.NewSet(audiences...)
		return func(c Claims) error {
			if v, ok := c.Get(ClaimAud); ok && v != nil {
				if aud, ok := v.([]string); ok {
					if expected.ContainsAll(internal.NewSet(aud...)) {
						return nil
					}
				}
			}
			return ErrInvalidAud
		}
	}
	// ExpectTime returns an Expect rule to check the time related claims "exp", "iat" and "nbf", if
	// they are available as time.Time. The rule considers a leeway in order to slack the clock. The
	// leeway must be a positive time.Duration, otherwise its absolute value is used.
	//
	// For "exp" claim, if current time is beyond the indicated expiry plus leeway, ErrExpExpired is returned;
	// For "iat" claim, if issued at time is beyond current time plus leeway, ErrIatInFuture is returned;
	// For "nbf" claim, if not before time is beyond current time plus leeway, ErrNbfTooSoon is returned.
	//
	// When time related claim is not present, or is not returned as time.Time by Claims, the validation is skipped.
	ExpectTime = func(leeway time.Duration) Expect {
		if leeway < 0 {
			leeway = -leeway
		}

		now := time.Now()

		return func(c Claims) error {
			if v, ok := c.Get(ClaimExp); ok {
				if exp, ok := v.(time.Time); ok && !exp.IsZero() {
					if now.After(exp.Add(leeway)) {
						return ErrExpExpired
					}
				}
			}

			if v, ok := c.Get(ClaimIat); ok {
				if iat, ok := v.(time.Time); ok && !iat.IsZero() {
					if iat.After(now.Add(leeway)) {
						return ErrIatInFuture
					}
				}
			}

			if v, ok := c.Get(ClaimNbf); ok {
				if nbf, ok := v.(time.Time); ok && !nbf.IsZero() {
					if nbf.After(now.Add(leeway)) {
						return ErrNbfTooSoon
					}
				}
			}

			return nil
		}
	}
)
