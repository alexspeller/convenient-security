# Protected SSH keys

Convenient Security can keep an SSH private key behind any registered secret
backend and expose it to Apple OpenSSH as a destination-bound signing identity.
The SSH socket returns public identities and signatures only; private-key bytes
never cross that socket.

This is currently a manual workflow. It does not modify shell startup files,
`~/.ssh/config`, launchd configuration, or another SSH agent.

## Protect an existing key

The convenient import path uses the native encrypted store by default:

```sh
csec protect --ssh ~/.ssh/id_ed25519
export SSH_AUTH_SOCK="$(csec ssh socket)"
ssh user@example.com
```

`csec protect --ssh` performs one trusted review and Touch ID operation for the
whole batch. It then:

1. reads only caller-owned, non-symlink regular files;
2. imports the private keys durably into the native blob destination;
3. parses them inside `csecd` and atomically registers their canonical
   `csec://` references plus public metadata;
4. writes ordinary `.csec` sidecars next to the original paths;
5. preserves an existing `.pub` file byte-for-byte, or creates one from the
   derived public metadata when it is missing; and
6. removes each original private-key file only if its identity, size, and
   modification time are unchanged since it was read.

The default native store is `ssh-keys`. The useful migration controls are:

```sh
csec protect --ssh --dry-run ~/.ssh/id_ed25519
csec protect --ssh --keep-plaintext ~/.ssh/id_ed25519
csec protect --ssh --store work-ssh ~/.ssh/id_work
```

If import or registration fails, csec does not write sidecars or remove the
originals. If a later filesystem step fails or a source changes during review,
the encrypted import remains recoverable and the original private key remains
in place; an unexpected retained plaintext makes the command exit nonzero and
names the retained path. Unlinking a file is not secure erasure on APFS or SSD
storage; backups, snapshots, synchronized copies, and previously copied data
remain outside csec's control.

## Register a key in any backend

Import and signing are separate. `csec protect --ssh` chooses a native import
destination for convenience, but SSH registration is backend-neutral:

```sh
csec ssh register 'op://Private/SSH key/private key'
csec ssh register 'future-provider://account/key'
csec ssh register ~/.ssh/id_ed25519.csec
```

The named provider must already be registered with `csecd`, and the reference
must resolve to one supported private-key document. Registration presents a
trusted value-free review, obtains Touch ID, resolves through `SecretResolver`,
derives the public identity, and persists only:

- the canonical `SecretRef` URI;
- the public-key blob and algorithm;
- its SHA-256 fingerprint; and
- a bounded display label.

No SSH code depends on native blob IDs, 1Password record IDs, or provider
internals. Adding another `SecretProvider` requires no SSH signing changes.

The `.csec` sidecar and the source backend retain their ordinary semantics.
This is intentionally not a separate hardware-backed or non-exportable key
store: someone can still deliberately request the referenced value through an
authorized generic csec delivery, or through the source backend's own tools.
The narrower guarantee is that the SSH-agent socket itself never exports the
private key and cannot be used for arbitrary signing.

## Manual socket and catalog commands

If csec is your SSH agent, put this in your shell profile. Otherwise, run it in
the current shell before the SSH commands that should use csec:

```sh
export SSH_AUTH_SOCK="$(csec ssh socket)"
# Equivalent:
eval "$(csec ssh env)"
```

After a successful `csec protect --ssh` or `csec ssh register`, csec checks the
launching shell's `SSH_AUTH_SOCK`. If it is unset or points elsewhere, the
command prints this profile/one-off guidance. It stays quiet when the shell is
already configured for the csec socket; it never edits a profile itself.

Catalog management stays on csec's authenticated JSON control socket rather
than the SSH wire protocol:

```sh
csec ssh status
csec ssh list
csec ssh register --label work 'op://Private/SSH key/private key'
csec ssh remove 'SHA256:...'
```

`remove` deletes only the public catalog registration and its live grants. It
does not delete the referenced value from its backend. `ssh-add` add/remove,
locking, agent chaining, global shell setup, and automatic SSH configuration are
not part of this first manual implementation. Setting `SSH_AUTH_SOCK` to csec's
socket also means identities from another agent are not visible through it.

## Approval and grant behavior

An import/registration approval proves that the reference contains the public
identity being catalogued. The first actual connection for a new authorization
tuple presents a separate trusted review before resolving the private key. The
tuple is:

- SSH public-key fingerprint;
- verified server host-key fingerprint;
- remote SSH username;
- the Apple SSH code identity and audit session; and
- the live parent process subtree.

The approved grant lasts at most 12 hours. Another Apple `ssh` process in that
same subtree may reuse it only for the same key, host key, and remote user. A
different key, host key, username, process root, expired process, or daemon
restart requires a new review. This makes repeated Git/SSH operations usable
without turning the agent into ambient same-user signing authority.

The agent protocol supplies the cryptographic host key, not the DNS hostname.
The trusted review therefore identifies the destination by host-key fingerprint.
Hosts that deliberately share one host key are indistinguishable at this layer.

## Signing boundary

The release SSH socket is created inside csec's private `0700` runtime directory
and is mode `0600`. Every connection must be the current user's live,
Apple-signed, hardened `/usr/bin/ssh` process (`com.apple.ssh`); a copied binary,
`ssh-add`, a Homebrew SSH build, and unrelated same-user processes are refused.
The daemon revalidates the socket audit token and code identity after an
asynchronous approval/signing operation and before returning a response.

Before policy review or provider resolution, the server requires and verifies
OpenSSH's `session-bind@openssh.com` message. It checks the server host-key
signature over the SSH session identifier, rejects forwarding, and accepts only
an exact SSH user-authentication signing packet whose session, key, algorithm,
service, method, username, and host-bound key are consistent. Unknown agent
messages and all SSH-wire catalog mutations fail closed. Agent frames are capped
at 256 KiB, and `csecd` disables core dumps before starting either socket.

After approval, the signing service resolves the canonical reference through
`SecretResolver`, reparses the private key, verifies that its public blob still
matches the catalog and the request, signs the exact validated authentication
packet, revalidates the caller/process root, and returns one SSH signature blob.

## Supported keys and current limits

The first release accepts one unencrypted private key in any of these encodings:

- OpenSSH `openssh-key-v1`;
- legacy PEM RSA PKCS#1 or EC SEC1; or
- PKCS#8 RSA, EC, or Ed25519.

Supported identities are Ed25519, ECDSA P-256/P-384/P-521, and RSA keys of at
least 2048 bits. RSA signatures require RSA-SHA2-256 or RSA-SHA2-512; SHA-1
`ssh-rsa` signatures are refused.

Encrypted private-key documents, DSA, Ed448, FIDO/SK keys, certificates,
multi-key OpenSSH files, unknown signature flags, forwarded agent use, and host
certificates are not supported. The catalog is capped at 64 identities. These
limits fail closed rather than silently falling back to ordinary signing.

The automated suite uses generated synthetic keys and a synthetic SSH-agent
connection. A signed/notarized physical-Mac run against a real local or remote
`sshd` remains a release gate; debug-build success is not evidence that the
shipping code-identity and Keychain boundaries are provisioned correctly.
