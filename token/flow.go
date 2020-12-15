package token

import (
	"errors"
)

var (
	ErrUnexpectedResponse = errors.New("sdk received unexpected response")
)

type FlowOpt struct {
}
