package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	onepassword "github.com/1password/onepassword-sdk-go"
)

func TestNamesPersonalVault(t *testing.T) {
	cases := map[string]bool{
		"op://Employee/Item/field":    true,
		"op://employee/Item/field":    true,
		"op://Private/Item/field":     true,
		"op://PRIVATE/Item/field":     true,
		"op://Engineering/Item/field": false,
		"op://Employees/Item/field":   false,
		"op://Employee":               false,
		"csec://store/key":            false,
		"":                            false,
	}
	for reference, want := range cases {
		if got := namesPersonalVault(reference); got != want {
			t.Errorf("namesPersonalVault(%q) = %v, want %v", reference, got, want)
		}
	}
}

func TestWithVaultRewritesOnlyTheVaultSegment(t *testing.T) {
	got := withVault("op://Employee/Slack Token/password", "abc123")
	want := "op://abc123/Slack Token/password"
	if got != want {
		t.Errorf("withVault = %q, want %q", got, want)
	}
	// A reference the rewriter cannot parse must come back untouched rather
	// than mangled into something that addresses a different secret.
	if got := withVault("not-a-reference", "abc123"); got != "not-a-reference" {
		t.Errorf("withVault mangled an unparseable reference: %q", got)
	}
}

func TestErrorResponseKinds(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{errors.New("vaultNotFound: no vault matched"), KindNotFound},
		{errors.New("itemNotFound"), KindNotFound},
		{errors.New("desktop app connection channel is closed"), KindUnavailable},
		{errors.New("connection was unexpectedly dropped by the desktop app"), KindUnavailable},
		{errors.New("something else entirely"), KindInternal},
	}
	for _, c := range cases {
		if got := errorResponse(7, c.err).Kind; got != c.want {
			t.Errorf("errorResponse(%v).Kind = %q, want %q", c.err, got, c.want)
		}
	}
	// The response must always carry the request id so csecd can correlate it.
	if got := errorResponse(7, errors.New("x")).ID; got != 7 {
		t.Errorf("errorResponse dropped the request id: %d", got)
	}
	if errorResponse(7, errors.New("x")).OK {
		t.Error("an error response must not be marked ok")
	}
}

func TestDesktopSessionExpiredIsClassified(t *testing.T) {
	// The SDK renews an expired desktop session transparently; csecd only sees
	// this kind when the renewal itself failed, and must not treat it as a
	// permanent failure of the reference.
	var expired error = &onepassword.DesktopSessionExpiredError{}
	if got := errorResponse(1, expired).Kind; got != KindSessionExpired {
		t.Errorf("expired session classified as %q, want %q", got, KindSessionExpired)
	}
}

func TestInvalidClientIsClassifiedSeparately(t *testing.T) {
	// The desktop SDK can lose its client handle without returning the typed
	// DesktopSessionExpired error. Reusing that handle will never recover.
	for _, err := range []error{
		errors.New("invalid client id"),
		fmt.Errorf("SDK invocation: %w", errors.New("invalid client id")),
		errors.New("an internal error occurred, please contact 1Password at support@1password.com or https://developer.1password.com/joinslack: invalid client id"),
		errors.New(`{"name":"Internal","message":"invalid client id"}`),
	} {
		if got := errorResponse(9, err).Kind; got != "client_invalidated" {
			t.Errorf("errorResponse(%v).Kind = %q, want client_invalidated", err, got)
		}
	}
	// Neither a reference containing the phrase nor an authorization refusal
	// is permission to reconnect and retry.
	for _, err := range []error{
		errors.New("fieldNotFound: invalid client id"),
		errors.New("authorization denied"),
		errors.New(`{"name":"Unauthorized","message":"invalid client id"}`),
	} {
		if got := errorResponse(9, err).Kind; got == "client_invalidated" {
			t.Errorf("errorResponse(%v) incorrectly permits session recovery", err)
		}
	}
}

func TestIsVaultNotFoundIsCaseInsensitive(t *testing.T) {
	if !isVaultNotFound(errors.New("VaultNotFound")) {
		t.Error("expected VaultNotFound to be recognised")
	}
	if isVaultNotFound(errors.New("itemNotFound")) {
		t.Error("itemNotFound must not be treated as a vault miss")
	}
}

func TestVaultResponseCarriesTypeButNoContent(t *testing.T) {
	// The vault type is what lets csecd's index agree with the resolve path's
	// personal-vault aliasing. Nothing else about the vault travels.
	encoded, err := json.Marshal(Response{ID: 3, OK: true, Vaults: []Vault{
		{ID: "v1", Title: "Employee", Type: string(onepassword.VaultTypePersonal)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":3,"ok":true,"vaults":[{"id":"v1","title":"Employee","type":"personal"}]}`
	if string(encoded) != want {
		t.Errorf("vault response = %s, want %s", encoded, want)
	}
}

func TestSeedProbeOnlyForReferencesWithoutAQuery(t *testing.T) {
	probe, ok := seedProbeReference("op://Private/npm/one-time password")
	if !ok || probe != "op://Private/npm/one-time password?attribute=otp" {
		t.Errorf("seedProbeReference = %q, %v; want the reference asking for its code", probe, ok)
	}
	// The SDK takes one query parameter, so a reference that already has one
	// (a code, an SSH key format) is never probed.
	for _, reference := range []string{
		"op://Private/npm/one-time password?attribute=otp",
		"op://Private/key/private key?ssh-format=openssh",
	} {
		if _, ok := seedProbeReference(reference); ok {
			t.Errorf("seedProbeReference(%q) probed a reference that has a query", reference)
		}
	}
}

func TestProbeFindsSeedOnlyOnTOTPFields(t *testing.T) {
	probe := "op://v/i/f?attribute=otp"
	answer := func(content *onepassword.ResolvedReference, failure onepassword.ResolveReferenceErrorTypes) onepassword.ResolveAllResponse {
		var response onepassword.Response[onepassword.ResolvedReference, onepassword.ResolveReferenceError]
		response.Content = content
		if failure != "" {
			response.Error = &onepassword.ResolveReferenceError{Type: failure}
		}
		return onepassword.ResolveAllResponse{
			IndividualResponses: map[string]onepassword.Response[onepassword.ResolvedReference, onepassword.ResolveReferenceError]{
				probe: response,
			},
		}
	}
	code := &onepassword.ResolvedReference{Secret: "123456"}
	if !probeFindsSeed(answer(code, ""), probe, nil) {
		t.Error("a probe that returned a code must mark the field a TOTP seed")
	}
	if !probeFindsSeed(answer(nil, onepassword.ResolveReferenceErrorTypeVariantUnableToGenerateTOTPCode), probe, nil) {
		t.Error("a TOTP field whose seed cannot make a code is still a seed")
	}
	for _, other := range []onepassword.ResolveReferenceErrorTypes{
		onepassword.ResolveReferenceErrorTypeVariantIncompatibleTOTPQueryParameterField,
		onepassword.ResolveReferenceErrorTypeVariantFieldNotFound,
		onepassword.ResolveReferenceErrorTypeVariantParsing,
	} {
		if probeFindsSeed(answer(nil, other), probe, nil) {
			t.Errorf("a probe refused with %q must leave the field ordinary", other)
		}
	}
	if probeFindsSeed(answer(code, ""), probe, errors.New("desktop app connection channel is closed")) {
		t.Error("a failed probe call must never withhold the value")
	}
	if probeFindsSeed(onepassword.ResolveAllResponse{}, probe, nil) {
		t.Error("an empty probe answer must leave the field ordinary")
	}
	// The one answer counts even when the SDK keys it by another spelling.
	rekeyed := answer(code, "")
	rekeyed.IndividualResponses = map[string]onepassword.Response[onepassword.ResolvedReference, onepassword.ResolveReferenceError]{
		"op://vault-id/item-id/field-id?attribute=otp": rekeyed.IndividualResponses[probe],
	}
	if !probeFindsSeed(rekeyed, probe, nil) {
		t.Error("a single probe answer under another key must still be read")
	}
}
