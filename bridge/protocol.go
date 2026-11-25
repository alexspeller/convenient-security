// Package main implements csec-op-bridge: a long-lived holder of one
// 1Password SDK desktop-app client.
//
// It exists because the `op` CLI has no persistent session. Every `op`
// invocation re-authorizes against the desktop app, and an authorization
// request made while the app is locked *unlocks the app* — which is a Touch ID
// prompt. A resident agent that polls the CLI therefore raises prompts the user
// never asked for. One SDK client, held open, replaces that with a single
// authorization whose lifetime csecd controls.
package main

// Request is one line of newline-delimited JSON on stdin.
type Request struct {
	ID uint64 `json:"id"`
	Op string `json:"op"`
	// Reference is the op:// URI to resolve. Only meaningful for OpResolve.
	Reference string `json:"reference,omitempty"`
	// VaultID selects the vault to list. Only meaningful for OpItems.
	VaultID string `json:"vault_id,omitempty"`
}

// Response is one line of newline-delimited JSON on stdout. Exactly one
// response is written per request, in order.
type Response struct {
	ID uint64 `json:"id"`
	OK bool   `json:"ok"`
	// Value carries a resolved secret. It travels on this pipe and nowhere
	// else: never argv, never the environment, never stderr, never a log.
	Value  *string `json:"value,omitempty"`
	Vaults []Vault `json:"vaults,omitempty"`
	Items  []Item  `json:"items,omitempty"`
	// Kind is a bounded, bridge-authored classification. Message is the
	// underlying text, which csecd treats as untrusted metadata.
	Kind    string `json:"kind,omitempty"`
	Message string `json:"message,omitempty"`
}

// Vault is value-free vault metadata used to decide which account owns a
// reference. It deliberately carries no item, field, or secret content.
type Vault struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// Type is the SDK's vault classification ("personal", "userCreated", ...).
	// csecd needs it to treat a reference that names a personal vault by the
	// spelling this account does not use ("Employee" vs "Private") the same
	// way the resolve path already does.
	Type string `json:"type,omitempty"`
}

// Item is value-free item identity, used only to decide which of two
// same-named vaults in different accounts actually holds a reference. It
// carries no field, section, or secret content.
type Item struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

const (
	// OpResolve resolves one op:// reference to its value.
	OpResolve = "resolve"
	// OpVaults lists the account's vaults. It doubles as the keepalive: it is
	// the cheapest call that provably touches the desktop session, so a
	// successful vault list both refreshes the ten-minute idle window and
	// refreshes csecd's vault→account index.
	OpVaults = "vaults"
	// OpItems lists a vault's item identities. Used only to break a tie when
	// the same vault name exists in more than one signed-in account.
	OpItems = "items"
	// OpShutdown releases the client and exits.
	OpShutdown = "shutdown"
)

// Error kinds. csecd maps these to its own diagnostics; the set is closed so
// that provider text can never carry unbounded upstream output.
const (
	KindSessionExpired    = "session_expired"
	KindClientInvalidated = "client_invalidated"
	KindNotFound          = "not_found"
	KindUnauthorized      = "unauthorized"
	KindUnavailable       = "unavailable"
	KindInvalidRequest    = "invalid_request"
	KindInternal          = "internal"
	// KindOTPSeed: the reference names a TOTP-type field, whose value is the
	// 2FA seed; the bridge never sends it (csec-0.65).
	KindOTPSeed = "otp_seed"
)
