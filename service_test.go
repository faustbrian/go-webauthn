package webauthn_test

import (
	"errors"
	"testing"

	webauthn "github.com/faustbrian/go-webauthn"
)

func TestServiceCannotExposeCeremoniesWithoutDurableStore(t *testing.T) {
	service, err := webauthn.New(webauthn.Config{}, webauthn.Dependencies{})
	var invalid webauthn.Invalid
	if service != nil || !errors.As(err, &invalid) {
		t.Fatal("construction without explicit durable dependencies must fail closed")
	}
}
