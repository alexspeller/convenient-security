#!/usr/bin/env bash

# The Apple team and identifier csec is built and signed under, read from
# identity.xcconfig (the repository root in a checkout; beside this file in the
# package's support directory and its install scripts). The build stages and
# the scripts the package ships source this file and call csec_identity_load,
# so the team ID and identifier are written in that one file only.
#
# The file is parsed, never sourced: root runs some of these scripts, and only
# a 10-character team ID and a reverse-DNS identifier are accepted.

# Loads an identity.xcconfig ($1) and sets:
#   csec_team_id                 the Apple team ID
#   csec_identifier              the identifier prefix (the app's bundle ID)
#   csec_keychain_access_group   TEAM.IDENTIFIER
#   csec_cloudkit_container      iCloud.IDENTIFIER
#   csec_product_requirement     the code requirement every product binary meets
#                                (and its identifier clause added to it)
# Prints the problem and returns 1 on a missing or malformed file.
csec_identity_load() {
  local file="$1" line name value team="" identifier=""
  if [ ! -f "$file" ]; then
    echo "identity: $file not found" >&2
    return 1
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "" | //*) continue ;;
    esac
    if [[ ! "$line" =~ ^([A-Z_]+)[[:space:]]*=[[:space:]]*([^[:space:]]+)[[:space:]]*$ ]]; then
      echo "identity: $file: not a comment or NAME = value line: $line" >&2
      return 1
    fi
    name="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    case "$name" in
      CSEC_TEAM_ID)
        [ -z "$team" ] || { echo "identity: $file sets $name twice" >&2; return 1; }
        team="$value"
        ;;
      CSEC_IDENTIFIER)
        [ -z "$identifier" ] || { echo "identity: $file sets $name twice" >&2; return 1; }
        identifier="$value"
        ;;
      *)
        echo "identity: $file: unknown setting $name" >&2
        return 1
        ;;
    esac
  done <"$file"
  if [[ ! "$team" =~ ^[A-Z0-9]{10}$ ]]; then
    echo "identity: $file: CSEC_TEAM_ID must be a 10-character Apple team ID" >&2
    return 1
  fi
  if [[ ! "$identifier" =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]]; then
    echo "identity: $file: CSEC_IDENTIFIER must be a reverse-DNS identifier such as com.example.csec" >&2
    return 1
  fi
  csec_team_id="$team"
  csec_identifier="$identifier"
  csec_keychain_access_group="$team.$identifier"
  csec_cloudkit_container="iCloud.$identifier"
  csec_product_requirement="anchor apple generic and certificate leaf[subject.OU] = \"$team\""
}

# Copies a template ($1) to $2 with @CSEC_TEAM_ID@ and @CSEC_IDENTIFIER@
# filled in from the loaded identity, refusing one left with a placeholder.
csec_identity_render() {
  local template="$1" output="$2"
  : "${csec_team_id:?csec_identity_load first}" "${csec_identifier:?csec_identity_load first}"
  /usr/bin/sed \
    -e "s/@CSEC_TEAM_ID@/$csec_team_id/g" \
    -e "s/@CSEC_IDENTIFIER@/$csec_identifier/g" \
    "$template" >"$output"
  if /usr/bin/grep -q '@CSEC_[A-Z_]*@' "$output"; then
    echo "identity: $output still has an unfilled placeholder" >&2
    return 1
  fi
}

# The Swift source generated from the loaded identity (Swift cannot read the
# xcconfig itself). bin/ci fails when the checked-in copy differs.
csec_identity_swift() {
  : "${csec_team_id:?csec_identity_load first}" "${csec_identifier:?csec_identity_load first}"
  cat <<EOF
// Generated from identity.xcconfig by packaging/lib/identity.sh; do not edit.
// The build stages rewrite it from that file, and bin/ci fails when the two
// disagree. The names derived from these two are in DerivedIdentity.swift.

public enum CSECBuildIdentity {
    /// The Apple team every product binary is signed by.
    public static let teamIdentifier = "$csec_team_id"
    /// The identifier prefix: the app's bundle ID and the root of every other name.
    public static let identifier = "$csec_identifier"
}
EOF
}

# Rewrites the generated Swift source ($1) when it differs from the loaded
# identity, and says so; leaves it untouched otherwise.
csec_identity_write_swift() {
  local destination="$1" expected
  expected="$(csec_identity_swift)"
  if [ -f "$destination" ] && [ "$(cat "$destination")" = "$expected" ]; then
    return 0
  fi
  printf '%s\n' "$expected" >"$destination"
  echo "identity: rewrote $destination for team $csec_team_id, identifier $csec_identifier"
}
