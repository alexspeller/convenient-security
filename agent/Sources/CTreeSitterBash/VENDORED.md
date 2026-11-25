# Vendored tree-sitter and tree-sitter-bash

These sources are copied unmodified from the crates.io packages that Codex
links, so csec's Codex hook parses shell commands with the same parser and
grammar as Codex's own command checks (`codex-rs/shell-command/src/bash.rs`).
Codex's `Cargo.lock` pins both packages at tag `rust-v0.155.0-alpha.9.2` and on
`main` as of 2026-09. Re-checked 2026-09-24: the pins are identical at
`rust-v0.155.0-alpha.16.4` (the Codex in ChatGPT.app) and `rust-v0.156.1` (the
npm CLI).

| Package | Version | crates.io checksum (sha256 of the `.crate`, as in Codex's Cargo.lock) | Upstream commit |
| --- | --- | --- | --- |
| `tree-sitter` (runtime, `lib/` of github.com/tree-sitter/tree-sitter) | 0.25.10 | `78f873475d258561b06f1c595d93308a7ed124d9977cb26b148c2084a4a3cc87` | `da6fe9beb4f7f67beb75914ca8e0d48ae48d6406` |
| `tree-sitter-bash` (github.com/tree-sitter/tree-sitter-bash) | 0.25.1 | `9e5ec769279cc91b561d3df0d8a5deb26b0ad40d183127f409494d6d8fc53062` | `a06c2e4415e9bc0346c6b86d401879ffb44058f7` |

The files, relative to this directory:

- `include/tree_sitter/api.h` is the runtime's `include/tree_sitter/api.h`.
- `tree-sitter/src/` is the runtime's `src/`, without its `wasm/` directory,
  which is only used when `TREE_SITTER_FEATURE_WASM` is defined. Codex does
  not define it.
- `tree-sitter-bash/src/` holds the grammar's `parser.c`, `scanner.c` and
  `tree_sitter/*.h`.
- `tree-sitter/LICENSE` is the MIT license at the runtime's upstream commit,
  because the runtime crate does not ship one. `tree-sitter-bash/LICENSE` is
  the MIT license from the grammar crate. `tree-sitter/src/unicode/LICENSE`
  is the ICU license for the Unicode headers in that directory.
- `include/CTreeSitterBash.h` is csec's own module header. It declares
  `tree_sitter_bash()`.

Only `tree-sitter/src/lib.c` (the runtime's amalgamation, which `#include`s
every other runtime `.c` file), `tree-sitter-bash/src/parser.c`, and
`tree-sitter-bash/src/scanner.c` are compiled. The defines in `Package.swift`
are the runtime's own (`binding_rust/build.rs`).

sha256 of the main files:

```
6bca070a6a70740c8e8af244af8a7311dbea09fbb60372376f5260facaf785f0  tree-sitter/src/lib.c
937c5389713f99318ac7adbdb3a95e9976bbd211e35e37ed5df878f29aa86c30  include/tree_sitter/api.h
5ad30bb1a260c76df5397490b8bd97e272e62ed9c99be36fa53da959d7667e7f  tree-sitter-bash/src/parser.c
7cc25d70626f8939b35ecd504bf724e2001b817412aa29bceb4c4955a91558a9  tree-sitter-bash/src/scanner.c
```

To update, when Codex's `Cargo.lock` moves:
1. Unpack the new `.crate` files and check their sha256 against Codex's `Cargo.lock`.
2. Replace these files with the new ones.
3. Regenerate the parity vectors in `cs-selftest/CodexCommandGateTests.swift`
   from Codex's own crates.
