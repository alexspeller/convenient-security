# Convenient Security agent instructions

Read `CLAUDE.md` before changing this repository. It contains the project ethos,
threat model, and credential-handling discipline.

## Backend-agnostic storage

This is a fundamental invariant, not an implementation preference: storage and
delivery are separate concerns. Every authorization, policy, and
delivery feature must operate on a canonical `SecretRef` and resolve it through
`SecretResolver` / `SecretProvider` only after authorization. It must not depend
on `csec://`, `op://`, `NativeEncryptedFileProvider`, `NativeBlobStore`, or any
other particular backend.

- Native storage, 1Password, and future providers are equally valid sources.
- Protocols, catalogs, grants, and sidecars store canonical references plus
  bounded value-free metadata, never provider-private record identifiers.
- Provider-specific import and write behavior belongs behind a destination or
  provider adapter. A backend without write support may still participate when
  the user registers an existing reference.
- A command such as `csec protect` may choose or default an import destination,
  but the resulting consumer registration must retain only the canonical
  reference and must also accept an existing reference from any provider.
- Adding a new backend must not require changes to SSH signing or any other
  consumer/delivery adapter.
- Resolve only after the complete delivery or signing request has passed policy
  and consent. Keep resolved values inside the narrow delivery implementation.
- Tests for a new delivery adapter must prove backend neutrality with injected
  providers or references from more than one scheme.

For example, the SSH agent catalog records a `SecretRef` and public-key metadata.
At signing time the daemon resolves that reference through the normal provider
abstraction and returns only a signature; it never assumes the key is a native
blob.
