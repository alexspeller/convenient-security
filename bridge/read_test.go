package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	onepassword "github.com/1password/onepassword-sdk-go"
)

// fakeSecrets stands in for the SDK's Secrets API and counts round trips, each
// of which is a call to the desktop app in the real bridge.
type fakeSecrets struct {
	values map[string]string // reference → value
	seeds  map[string]bool   // references whose field is TOTP-typed
	// failAll fails every call as a whole, as the SDK does for the session.
	failAll error
	// rekey answers ResolveAll under keys other than the ones asked for.
	rekey bool
	calls []string
}

func (f *fakeSecrets) answer(reference string) onepassword.Response[onepassword.ResolvedReference, onepassword.ResolveReferenceError] {
	var response onepassword.Response[onepassword.ResolvedReference, onepassword.ResolveReferenceError]
	fail := func(kind onepassword.ResolveReferenceErrorTypes) {
		response.Error = &onepassword.ResolveReferenceError{Type: kind}
	}
	if field, ok := strings.CutSuffix(reference, "?attribute=otp"); ok {
		switch {
		case f.seeds[field]:
			response.Content = &onepassword.ResolvedReference{Secret: "123456"}
		case f.values[field] != "":
			fail(onepassword.ResolveReferenceErrorTypeVariantIncompatibleTOTPQueryParameterField)
		default:
			fail(onepassword.ResolveReferenceErrorTypeVariantVaultNotFound)
		}
		return response
	}
	if value, ok := f.values[reference]; ok {
		response.Content = &onepassword.ResolvedReference{Secret: value}
		return response
	}
	fail(onepassword.ResolveReferenceErrorTypeVariantVaultNotFound)
	return response
}

func (f *fakeSecrets) Resolve(_ context.Context, reference string) (string, error) {
	f.calls = append(f.calls, "Resolve "+reference)
	if f.failAll != nil {
		return "", f.failAll
	}
	answer := f.answer(reference)
	if answer.Error != nil {
		return "", errors.New("error resolving secret reference: " + string(answer.Error.Type))
	}
	return answer.Content.Secret, nil
}

func (f *fakeSecrets) ResolveAll(_ context.Context, references []string) (onepassword.ResolveAllResponse, error) {
	f.calls = append(f.calls, "ResolveAll "+strings.Join(references, " "))
	if f.failAll != nil {
		return onepassword.ResolveAllResponse{}, f.failAll
	}
	response := onepassword.ResolveAllResponse{
		IndividualResponses: map[string]onepassword.Response[onepassword.ResolvedReference, onepassword.ResolveReferenceError]{},
	}
	for i, reference := range references {
		key := reference
		if f.rekey {
			key = "op://vault-id/item-id/field-" + string(rune('a'+i))
		}
		response.IndividualResponses[key] = f.answer(reference)
	}
	return response, nil
}

// fakeVaults lists one personal vault; nothing else of VaultsAPI is used.
type fakeVaults struct {
	onepassword.VaultsAPI
	personal string
	lists    int
}

func (f *fakeVaults) List(context.Context, ...onepassword.VaultListParams) ([]onepassword.VaultOverview, error) {
	f.lists++
	return []onepassword.VaultOverview{{ID: f.personal, Title: "Private", VaultType: onepassword.VaultTypePersonal}}, nil
}

func readThrough(t *testing.T, secrets *fakeSecrets, reference string) (string, bool, error) {
	t.Helper()
	b := &bridge{account: "test"}
	return b.read(context.Background(), secrets, &fakeVaults{personal: "personal-id"}, reference)
}

func TestQueryFreeReadIsOneSDKCall(t *testing.T) {
	reference := "op://Shared/db/password"
	secrets := &fakeSecrets{values: map[string]string{reference: "value"}}
	value, seed, err := readThrough(t, secrets, reference)
	if err != nil || value != "value" || seed {
		t.Fatalf("read = %q, seed %v, %v; want the value, not a seed", value, seed, err)
	}
	if len(secrets.calls) != 1 || !strings.HasPrefix(secrets.calls[0], "ResolveAll ") {
		t.Errorf("an ordinary first read made %d SDK calls %q; want one ResolveAll", len(secrets.calls), secrets.calls)
	}
}

func TestSeedVerdictComesFromTheSameCall(t *testing.T) {
	reference := "op://Private/npm/one-time password"
	secrets := &fakeSecrets{
		values: map[string]string{reference: "otpauth://totp/npm"},
		seeds:  map[string]bool{reference: true},
	}
	_, seed, err := readThrough(t, secrets, reference)
	if err != nil || !seed {
		t.Fatalf("read of a TOTP field: seed %v, %v; want it marked a seed", seed, err)
	}
	if len(secrets.calls) != 1 {
		t.Errorf("a seed field took %d SDK calls %q; want one", len(secrets.calls), secrets.calls)
	}
}

func TestReferenceWithAQueryIsOneResolve(t *testing.T) {
	reference := "op://Private/npm/one-time password?attribute=otp"
	secrets := &fakeSecrets{seeds: map[string]bool{"op://Private/npm/one-time password": true}}
	value, seed, err := readThrough(t, secrets, reference)
	if err != nil || value != "123456" || seed {
		t.Fatalf("code read = %q, seed %v, %v; want the code, not a seed", value, seed, err)
	}
	if len(secrets.calls) != 1 || !strings.HasPrefix(secrets.calls[0], "Resolve ") {
		t.Errorf("a code read made SDK calls %q; want one Resolve", secrets.calls)
	}
}

func TestPersonalVaultRetryStaysBatched(t *testing.T) {
	secrets := &fakeSecrets{values: map[string]string{"op://personal-id/gh/token": "value"}}
	value, seed, err := readThrough(t, secrets, "op://Employee/gh/token")
	if err != nil || value != "value" || seed {
		t.Fatalf("read = %q, seed %v, %v; want the personal vault's value", value, seed, err)
	}
	want := []string{
		"ResolveAll op://Employee/gh/token op://Employee/gh/token?attribute=otp",
		"ResolveAll op://personal-id/gh/token op://personal-id/gh/token?attribute=otp",
	}
	if strings.Join(secrets.calls, "\n") != strings.Join(want, "\n") {
		t.Errorf("personal-vault retry calls = %q; want %q", secrets.calls, want)
	}
}

func TestSessionFailureIsNotRetried(t *testing.T) {
	secrets := &fakeSecrets{failAll: errors.New("desktop app connection channel is closed")}
	_, _, err := readThrough(t, secrets, "op://Shared/db/password")
	if err == nil || errorResponse(0, err).Kind != KindUnavailable {
		t.Fatalf("read error = %v; want the session failure", err)
	}
	if len(secrets.calls) != 1 {
		t.Errorf("a session failure made SDK calls %q; a retry could raise a second prompt", secrets.calls)
	}
}

func TestMissKeepsResolveErrorKind(t *testing.T) {
	secrets := &fakeSecrets{}
	_, _, err := readThrough(t, secrets, "op://Shared/missing/password")
	if err == nil || errorResponse(0, err).Kind != KindNotFound {
		t.Fatalf("read error = %v; want a not-found kind", err)
	}
}

func TestOtherWholeCallFailureFallsBackToResolve(t *testing.T) {
	reference := "op://Shared/db/password"
	secrets := &fakeSecrets{values: map[string]string{reference: "value"}}
	b := &bridge{account: "test"}
	flaky := &flakyBatch{fakeSecrets: secrets}
	value, seed, err := b.read(context.Background(), flaky, &fakeVaults{}, reference)
	if err != nil || value != "value" || seed {
		t.Fatalf("read = %q, seed %v, %v; want the value read on its own", value, seed, err)
	}
}

// flakyBatch fails its first ResolveAll with an error that is not about the
// session, as a probe the SDK cannot parse might.
type flakyBatch struct {
	*fakeSecrets
	failed bool
}

func (f *flakyBatch) ResolveAll(ctx context.Context, references []string) (onepassword.ResolveAllResponse, error) {
	if !f.failed {
		f.failed = true
		return onepassword.ResolveAllResponse{}, errors.New("unexpected batch failure")
	}
	return f.fakeSecrets.ResolveAll(ctx, references)
}

func TestRekeyedBatchStillReadsTheValue(t *testing.T) {
	reference := "op://Shared/db/password"
	secrets := &fakeSecrets{values: map[string]string{reference: "value"}, rekey: true}
	value, seed, err := readThrough(t, secrets, reference)
	if err != nil || value != "value" || seed {
		t.Fatalf("read = %q, seed %v, %v; want the value read on its own", value, seed, err)
	}
}
