#ifndef CTREESITTERBASH_H
#define CTREESITTERBASH_H

// The tree-sitter runtime and the tree-sitter-bash grammar at the exact
// versions Codex links (see VENDORED.md), so csec parses a shell command the
// same way Codex's command checks do.
#include "tree_sitter/api.h"

/// The bash grammar, defined in tree-sitter-bash/src/parser.c.
const TSLanguage *tree_sitter_bash(void);

#endif
