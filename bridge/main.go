package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
)

// canonicalLibPath is the only 1Password IPC library this bridge will let the
// SDK load. The SDK also searches ~/Applications, which is writable by the
// user this process runs as — the same uid an opportunistic supply-chain
// attacker already has. Requiring the root-owned copy under /Applications, and
// refusing to start without it, keeps that fallback unreachable. csecd
// separately verifies this file's code signature before spawning the bridge.
const canonicalLibPath = "/Applications/1Password.app/Contents/Frameworks/libop_sdk_ipc_client.dylib"

const (
	integrationName    = "Convenient Security (csec)"
	integrationVersion = "v0.1.0"
)

// diag is the bridge's diagnostic channel. It writes to stderr, which csecd
// reads line by line and forwards to the unified log, so every line here must
// be value-free: identifiers, operation names, durations, error kinds. The
// SDK's own error text is passed along because csecd bounds and sanitizes it
// before logging, and because it is the only record of *why* 1Password refused
// something. csecd logs a line in the clear only when it has one of the shapes
// it knows (OnePasswordBridgeDiagnostic.fromStderr), minus the account UUID and
// any error text after a colon; anything else is logged private, so a changed
// line here loses its readability in the log until that function learns it.
var diag = log.New(os.Stderr, "", 0)

func diagf(format string, args ...any) {
	diag.Printf(time.Now().UTC().Format("15:04:05.000")+" "+format, args...)
}

// slowRequest is the duration past which a request has almost certainly not
// been served by a warm session. A held desktop session answers in well under
// a second; the SDK re-creates its client — an authorization, so a prompt —
// when the session has expired, and does so silently inside the call. Timing
// is the only signal the bridge has that it happened.
const slowRequest = time.Second

func main() {
	if len(os.Args) != 2 || os.Args[1] == "" {
		fmt.Fprintln(os.Stderr, "usage: csec-op-bridge <account-uuid>")
		os.Exit(2)
	}
	// The account is an identifier, not a value: argv is the right place for
	// it, and resolved secrets never appear here.
	account := os.Args[1]

	if err := checkCanonicalLib(); err != nil {
		diagf("refusing to start: %v", err)
		os.Exit(3)
	}

	diagf("started pid=%d account=%s", os.Getpid(), account)
	b := &bridge{account: account}
	defer b.close()

	if err := b.serve(os.Stdin, os.Stdout); err != nil {
		diagf("exiting: %v", err)
		os.Exit(1)
	}
	diagf("exiting: stdin closed or shutdown requested")
}

// checkCanonicalLib refuses anything but a regular file at the pinned path, so
// a symlink planted by same-uid malware cannot redirect the load.
func checkCanonicalLib() error {
	info, err := os.Lstat(canonicalLibPath)
	if err != nil {
		return fmt.Errorf("1Password desktop app not installed at %s", canonicalLibPath)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", canonicalLibPath)
	}
	return verifyCanonicalLib()
}

type bridge struct {
	account string

	mu     sync.Mutex
	client *onepassword.Client
	// personalVaultID is this account's own personal vault, looked up only
	// when a reference names a personal vault by the spelling this account
	// does not use. Empty until needed; "-" once known to be unavailable.
	personalVaultID string
}

// serve reads one request per line and writes exactly one response per line,
// in order. Requests are handled serially: two concurrent authorizations would
// mean two prompts racing each other in front of the user.
func (b *bridge) serve(in *os.File, out *os.File) error {
	scanner := bufio.NewScanner(in)
	// Secret values are bounded by 1Password's own item limits, but a generous
	// buffer keeps a large field from truncating into a parse error.
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	writer := bufio.NewWriter(out)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			// A malformed line has no id to correlate against, so answer on
			// id 0 rather than guessing.
			b.write(writer, Response{ID: 0, OK: false, Kind: KindInvalidRequest, Message: "malformed request"})
			continue
		}
		if req.Op == OpShutdown {
			diagf("request id=%d op=shutdown", req.ID)
			b.write(writer, Response{ID: req.ID, OK: true})
			return nil
		}
		started := time.Now()
		resp := b.handle(context.Background(), req)
		b.logOutcome(req, resp, time.Since(started))
		b.write(writer, resp)
	}
	// EOF means csecd is gone. Exiting releases the client and, with it, the
	// desktop session this process was holding.
	return scanner.Err()
}

// logOutcome records one request's result and duration, never its value.
func (b *bridge) logOutcome(req Request, resp Response, took time.Duration) {
	suffix := ""
	if took >= slowRequest {
		suffix = " (slower than a warm session; 1Password re-authorized or prompted)"
	}
	if resp.OK {
		diagf("request id=%d op=%s ok took=%s%s", req.ID, req.Op, took.Round(time.Millisecond), suffix)
		return
	}
	diagf("request id=%d op=%s failed kind=%s took=%s%s: %s",
		req.ID, req.Op, resp.Kind, took.Round(time.Millisecond), suffix, resp.Message)
}

func (b *bridge) write(w *bufio.Writer, resp Response) {
	encoded, err := json.Marshal(resp)
	if err != nil {
		// Marshalling a response can only fail on the value, which must not be
		// described in an error. Report the failure without it.
		encoded, _ = json.Marshal(Response{ID: resp.ID, OK: false, Kind: KindInternal, Message: "response encoding failed"})
	}
	w.Write(encoded)
	w.WriteByte('\n')
	w.Flush()
}

func (b *bridge) handle(ctx context.Context, req Request) Response {
	b.mu.Lock()
	defer b.mu.Unlock()

	client, err := b.ensureClient(ctx)
	if err != nil {
		return errorResponse(req.ID, err)
	}

	switch req.Op {
	case OpResolve:
		if req.Reference == "" {
			return Response{ID: req.ID, OK: false, Kind: KindInvalidRequest, Message: "missing reference"}
		}
		value, seed, err := b.read(ctx, client.Secrets(), client.Vaults(), req.Reference)
		if err != nil {
			return errorResponse(req.ID, err)
		}
		if seed {
			// The value is a 2FA seed, which csecd never releases: it is
			// dropped here, so it never crosses the pipe at all.
			return Response{ID: req.ID, OK: false, Kind: KindOTPSeed,
				Message: "the field is a one-time password; read it with ?attribute=otp"}
		}
		return Response{ID: req.ID, OK: true, Value: &value}

	case OpVaults:
		vaults, err := client.Vaults().List(ctx)
		if err != nil {
			return errorResponse(req.ID, err)
		}
		out := make([]Vault, 0, len(vaults))
		for _, v := range vaults {
			out = append(out, Vault{ID: v.ID, Title: v.Title, Type: string(v.VaultType)})
		}
		return Response{ID: req.ID, OK: true, Vaults: out}

	case OpItems:
		if req.VaultID == "" {
			return Response{ID: req.ID, OK: false, Kind: KindInvalidRequest, Message: "missing vault_id"}
		}
		items, err := client.Items().List(ctx, req.VaultID)
		if err != nil {
			return errorResponse(req.ID, err)
		}
		out := make([]Item, 0, len(items))
		for _, i := range items {
			out = append(out, Item{ID: i.ID, Title: i.Title})
		}
		return Response{ID: req.ID, OK: true, Items: out}

	default:
		return Response{ID: req.ID, OK: false, Kind: KindInvalidRequest, Message: "unknown op"}
	}
}

// ensureClient creates the client on first use. Creating it is what raises the
// authorization prompt, so it happens only in response to a request csecd
// chose to send — never on a timer of the bridge's own.
func (b *bridge) ensureClient(ctx context.Context) (*onepassword.Client, error) {
	if b.client != nil {
		return b.client, nil
	}
	diagf("authorizing: creating the SDK client for account=%s (1Password will prompt if this account is not already authorized)", b.account)
	started := time.Now()
	client, err := onepassword.NewClient(ctx,
		onepassword.WithDesktopAppIntegration(b.account),
		onepassword.WithIntegrationInfo(integrationName, integrationVersion),
	)
	if err != nil {
		diagf("authorization failed after %s: %v", time.Since(started).Round(time.Millisecond), err)
		return nil, err
	}
	diagf("authorized account=%s after %s", b.account, time.Since(started).Round(time.Millisecond))
	b.client = client
	return client, nil
}

func (b *bridge) close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.client = nil
}

// read resolves reference and reports whether it names a TOTP seed. Each SDK
// call is a round trip to the desktop app, so a reference without a query asks
// for its value and its seed probe in one ResolveAll, and a personal-vault miss
// retries the same way. A session-level failure is returned as it is: a second
// call could raise a second authorization prompt. Any other miss is read again
// on its own through resolve, whose error is the one errorResponse classifies.
func (b *bridge) read(ctx context.Context, secrets onepassword.SecretsAPI, vaults onepassword.VaultsAPI, reference string) (string, bool, error) {
	if _, ok := seedProbeReference(reference); ok {
		value, seed, failure, err := resolveWithProbe(ctx, secrets, reference)
		if err == nil && failure == "" {
			return value, seed, nil
		}
		if err != nil && sessionLevel(err) {
			return "", false, err
		}
		if failure == onepassword.ResolveReferenceErrorTypeVariantVaultNotFound && namesPersonalVault(reference) {
			if vaultID, lookupErr := b.lookupPersonalVault(ctx, vaults); lookupErr == nil && vaultID != "" {
				value, seed, failure, err := resolveWithProbe(ctx, secrets, withVault(reference, vaultID))
				if err == nil && failure == "" {
					return value, seed, nil
				}
				if err != nil && sessionLevel(err) {
					return "", false, err
				}
			}
		}
	}
	value, resolved, err := b.resolve(ctx, secrets, vaults, reference)
	if err != nil {
		return "", false, err
	}
	return value, isSeedField(ctx, secrets, resolved), nil
}

// resolveWithProbe asks for reference's value and its seed probe in one
// ResolveAll. failure is the SDK's reason when the value did not come back,
// "other" when the answer is missing from the response altogether.
func resolveWithProbe(ctx context.Context, secrets onepassword.SecretsAPI, reference string) (string, bool, onepassword.ResolveReferenceErrorTypes, error) {
	probe, _ := seedProbeReference(reference)
	response, err := secrets.ResolveAll(ctx, []string{reference, probe})
	if err != nil {
		return "", false, "", err
	}
	answer, ok := response.IndividualResponses[reference]
	switch {
	case !ok:
		diagf("resolve: the batched answer lacked the reference; reading it alone")
		return "", false, onepassword.ResolveReferenceErrorTypeVariantOther, nil
	case answer.Content == nil && answer.Error != nil:
		return "", false, answer.Error.Type, nil
	case answer.Content == nil:
		return "", false, onepassword.ResolveReferenceErrorTypeVariantOther, nil
	}
	return answer.Content.Secret, probeFindsSeed(response, probe, nil), "", nil
}

// sessionLevel reports whether err is about the desktop session rather than
// the reference, so trying the reference again cannot help.
func sessionLevel(err error) bool {
	switch errorResponse(0, err).Kind {
	case KindSessionExpired, KindClientInvalidated, KindUnauthorized, KindUnavailable:
		return true
	}
	return false
}

// isSeedField reports whether reference, which just resolved, names a
// TOTP-type field: its value is then the seed, whether an otpauth:// URI or a
// bare base32 secret. The SDK resolves "?attribute=otp" only on such a field
// and refuses it on any other, so one probe answers it. A reference that
// already carries a query is not probed (the SDK takes one parameter), and
// any probe failure but the SDK's own "could not generate a code" reads as an
// ordinary field: the probe only ever withholds a value, never adds one.
func isSeedField(ctx context.Context, secrets onepassword.SecretsAPI, reference string) bool {
	probe, ok := seedProbeReference(reference)
	if !ok {
		return false
	}
	response, err := secrets.ResolveAll(ctx, []string{probe})
	return probeFindsSeed(response, probe, err)
}

// seedProbeReference is reference asking for its one-time code, when it has
// no query of its own.
func seedProbeReference(reference string) (string, bool) {
	if strings.Contains(reference, "?") {
		return "", false
	}
	return reference + "?attribute=otp", true
}

// probeFindsSeed reads the ResolveAll answer for probe: a code means the field
// is TOTP-typed, as does a seed the SDK could not make a code from.
func probeFindsSeed(response onepassword.ResolveAllResponse, probe string, err error) bool {
	if err != nil {
		return false
	}
	answer, ok := response.IndividualResponses[probe]
	if !ok {
		if len(response.IndividualResponses) != 1 {
			return false
		}
		for _, only := range response.IndividualResponses {
			answer = only
		}
	}
	if answer.Content != nil {
		return true
	}
	return answer.Error != nil &&
		answer.Error.Type == onepassword.ResolveReferenceErrorTypeVariantUnableToGenerateTOTPCode
}

// resolve reads one reference, retrying a personal-vault miss against this
// account's real personal vault. It returns the value and the reference that
// produced it.
//
// A 1Password Business member's personal vault is titled "Employee" or
// "Private" depending on when the account was provisioned. `op` hides the
// difference by presenting every personal vault as "Employee", but the SDK
// uses the vault's own title — so a reference that worked through the CLI can
// come back vaultNotFound here. Treat both spellings as names for whichever
// personal vault this account actually has.
func (b *bridge) resolve(ctx context.Context, secrets onepassword.SecretsAPI, vaults onepassword.VaultsAPI, reference string) (string, string, error) {
	value, err := secrets.Resolve(ctx, reference)
	if err == nil {
		return value, reference, nil
	}
	if !isVaultNotFound(err) || !namesPersonalVault(reference) {
		return "", "", err
	}
	vaultID, lookupErr := b.lookupPersonalVault(ctx, vaults)
	if lookupErr != nil || vaultID == "" {
		// Report the original failure: the fallback not being available says
		// nothing useful about the reference the caller actually asked for.
		return "", "", err
	}
	retried := withVault(reference, vaultID)
	value, retryErr := secrets.Resolve(ctx, retried)
	if retryErr != nil {
		return "", "", err
	}
	return value, retried, nil
}

// lookupPersonalVault finds this account's single personal vault. More than
// one, or none, means the spelling cannot be disambiguated, and the caller
// keeps the original error.
func (b *bridge) lookupPersonalVault(ctx context.Context, vaults onepassword.VaultsAPI) (string, error) {
	if b.personalVaultID == "-" {
		return "", nil
	}
	if b.personalVaultID != "" {
		return b.personalVaultID, nil
	}
	listed, err := vaults.List(ctx)
	if err != nil {
		return "", err
	}
	found := ""
	for _, v := range listed {
		if v.VaultType != onepassword.VaultTypePersonal {
			continue
		}
		if found != "" {
			b.personalVaultID = "-"
			return "", nil
		}
		found = v.ID
	}
	if found == "" {
		b.personalVaultID = "-"
		return "", nil
	}
	b.personalVaultID = found
	return found, nil
}

var personalVaultTitles = map[string]bool{"employee": true, "private": true}

func namesPersonalVault(reference string) bool {
	rest, ok := strings.CutPrefix(reference, "op://")
	if !ok {
		return false
	}
	vault, _, ok := strings.Cut(rest, "/")
	if !ok {
		return false
	}
	return personalVaultTitles[strings.ToLower(vault)]
}

func withVault(reference string, vaultID string) string {
	rest, ok := strings.CutPrefix(reference, "op://")
	if !ok {
		return reference
	}
	_, tail, ok := strings.Cut(rest, "/")
	if !ok {
		return reference
	}
	return "op://" + vaultID + "/" + tail
}

func isVaultNotFound(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "vaultnotfound")
}

// An invalid handle cannot be renewed by reusing the SDK client. Recognize
// the SDK's plain and Internal JSON forms without treating a field name or
// an authorization refusal containing these words as a recoverable session.
func isInvalidClient(err error) bool {
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		message := cause.Error()
		var sdkError struct {
			Name    string `json:"name"`
			Message string `json:"message"`
		}
		if json.Unmarshal([]byte(message), &sdkError) == nil {
			if sdkError.Name != "Internal" {
				continue
			}
			message = sdkError.Message
		}
		lowered := strings.ToLower(strings.TrimSpace(message))
		if lowered == "invalid client id" ||
			(strings.HasPrefix(lowered, "an internal error occurred, please contact 1password at ") &&
				strings.HasSuffix(lowered, ": invalid client id")) {
			return true
		}
	}
	return false
}

// errorResponse maps an SDK error onto the closed set of kinds csecd
// understands. The message is carried for the daemon log; csecd bounds and
// sanitizes it before any of it reaches a user-facing surface.
func errorResponse(id uint64, err error) Response {
	var expired *onepassword.DesktopSessionExpiredError
	kind := KindInternal
	switch {
	case errors.As(err, &expired):
		kind = KindSessionExpired
	case isInvalidClient(err):
		kind = KindClientInvalidated
	default:
		lowered := strings.ToLower(err.Error())
		switch {
		case strings.Contains(lowered, "vaultnotfound"),
			strings.Contains(lowered, "itemnotfound"),
			strings.Contains(lowered, "sectionnotfound"),
			strings.Contains(lowered, "fieldnotfound"),
			strings.Contains(lowered, "not found"):
			kind = KindNotFound
		case strings.Contains(lowered, "channel is closed"),
			strings.Contains(lowered, "connection was unexpectedly dropped"),
			strings.Contains(lowered, "desktop application not found"):
			kind = KindUnavailable
		case strings.Contains(lowered, "authoriz"), strings.Contains(lowered, "denied"):
			kind = KindUnauthorized
		}
	}
	return Response{ID: id, OK: false, Kind: kind, Message: err.Error()}
}
