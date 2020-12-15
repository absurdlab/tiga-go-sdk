package oidc

import "errors"

const (
	DisplayPage  = "page"
	DisplayPopup = "popup"
	DisplayTouch = "touch"
	DisplayWap   = "wap"
)

var (
	// ErrInvalidDisplay indicates the display value is invalid
	ErrInvalidDisplay = errors.New("display is invalid")

	// ValidDisplay is the validation function for display.
	ValidDisplay = func(s string) error {
		switch s {
		case DisplayPage, DisplayPopup, DisplayTouch, DisplayWap:
			return nil
		default:
			return ErrInvalidDisplay
		}
	}
)
