#!/usr/bin/env bash

# Pure policy rendering and live-check evidence shared by the guarded installer
# and its hermetic tests.

# Reads a sudo_local on stdin; emits a complete candidate only after validation.
csec_sudo_policy() {
  /usr/bin/awk -v review="$1" -v guard="$2" -v tid="$3" '
    function reject(message) {
      print "sudo review policy: " message > "/dev/stderr"
      invalid = 1
    }
    {
      lines[NR] = $0
      if (NF && $1 !~ /^#/) active++
      if ($1 == "auth" && $2 == "sufficient" && $3 ~ /(^|\/)pam_tid[.]so$/ && !first_tid) first_tid = NR
      if ($1 !~ /^#/ && index($0, "pam_csec_sudo.so")) {
        if ($0 == review) { reviews++; review_at = NR; review_order = active }
        else if ($0 == guard) { guards++; guard_at = NR; guard_order = active }
        else reject("unrecognized csec entry")
      }
    }
    END {
      if (reviews > 1 || guards > 1) reject("duplicate csec entry")
      if (guards && (!reviews || guard_order != review_order + 1)) reject("guard must immediately follow the review")
      if (reviews && (!first_tid || first_tid < review_at)) reject("stock pam_tid must follow the review")
      if (invalid) exit 1
      for (i = 1; i <= NR; i++) {
        if (!reviews && i == first_tid) { print review; print guard }
        if (i == guard_at) continue
        print lines[i]
        if (i == review_at) print guard
      }
      if (!reviews && !first_tid) { print review; print guard; print tid }
    }
  '
}

# The removal's renderer: reads a sudo_local on stdin and emits it without the
# csec review and guard lines, refusing (and emitting nothing) when an active
# line names the module in any other form, which a person must look at. The
# rest of the stack, pam_tid included, stays as it is, so removing both lines
# always leaves Apple's own sudo authentication. Commented lines are inactive
# and stay.
csec_sudo_policy_removed() {
  /usr/bin/awk -v review="$1" -v guard="$2" '
    {
      lines[NR] = $0
      if ($1 !~ /^#/ && index($0, "pam_csec_sudo.so")) {
        if ($0 == review) reviews++
        else if ($0 == guard) guards++
        else {
          print "sudo review policy: unrecognized csec entry" > "/dev/stderr"
          invalid = 1
        }
      }
    }
    END {
      if (reviews > 1 || guards > 1) {
        print "sudo review policy: duplicate csec entry" > "/dev/stderr"
        invalid = 1
      }
      if (invalid) exit 1
      for (i = 1; i <= NR; i++) {
        if (lines[i] == review || lines[i] == guard) continue
        print lines[i]
      }
    }
  '
}

# The live check's evidence. A sudo's exit status cannot say which factor
# authenticated it: Apple's fallback or pam_tid approves a sudo the helper
# rejected, and another sudo's review can run beside this one. So the
# installer keeps an installation only on the value-free unified-log trail
# (docs/development.md, "Diagnosing a sudo review") of the one sudo it ran,
# found by that sudo's PID: the module's lines must end in the helper's
# approval, and the helper the module named must have been spawned by that
# sudo, approved, and exited 0. The module and helper log under the build
# identifier, so the caller loads the identity first (packaging/lib/identity.sh,
# csec_identity_load), which sets csec_identifier.

# Every log read goes through here, so the tests can replace it. Prints
# compact-style entries since $1 (`log show --start`) matching predicate $2.
csec_sudo_log_show() {
  /usr/bin/log show --start "$1" --style compact --predicate "$2"
}

# The message of each compact-style entry, oldest first; the header and
# anything not shaped like an entry are dropped.
csec_log_messages() {
  /usr/bin/awk '
    match($0, /^[0-9]+-[0-9]+-[0-9]+ [0-9:.]+ [A-Za-z]+ [^ []+\[[0-9]+:[0-9a-f]+\] \[[^]]*\] /) {
      print substr($0, RSTART + RLENGTH)
    }
  '
}

# What the module wrote inside the sudo with PID $2 since $1. Only
# /usr/bin/sudo loads the module, so a process that merely logs under the
# subsystem cannot supply these lines.
csec_sudo_module_trail() {
  csec_sudo_log_show "$1" "subsystem == \"$csec_identifier\" AND category == \"process-liveness\" AND processID == $2 AND processImagePath == \"/usr/bin/sudo\"" |
    csec_log_messages
}

# What the helper at path $3 with PID $2 wrote since $1. The PID is the
# binding: the module spawned the installed path suspended and checked its
# signature before resuming it. The unified log cannot name that path:
# logd attributes an image by its UUID, so the installed copy's lines carry
# the build tree's path once the build has run the identical binary. Only
# the process name, the basename, is the same for both copies.
csec_sudo_helper_trail() {
  csec_sudo_log_show "$1" "subsystem == \"$csec_identifier\" AND category == \"sudo-review\" AND processID == $2 AND process == \"${3##*/}\"" |
    csec_log_messages
}

# Reads one sudo's module messages on stdin. Prints the PID of the helper
# whose approval ended its authentication, or a reason and fails. The module
# logs `approved` only for a helper that exited 0 and then returns success, so
# a trail that goes on to anything else, a fallback above all, was not
# authenticated by the helper. A failed attempt before an approved retry is
# still an approval of this sudo.
csec_sudo_approving_helper() {
  /usr/bin/awk '
    NF == 0 { next }
    $0 == "sudo stage=review event=launch-started" { helper = "" }
    /^sudo stage=review event=signature-check-started pid=[1-9][0-9]*$/ {
      helper = substr($NF, 5)
    }
    { previous = last; last = $0; lines++ }
    END {
      if (!lines) { print "the module logged nothing for this sudo"; exit 1 }
      if (last != "sudo stage=review event=approved") {
        print "the module did not end with the review helper approving (last: " last ")"
        exit 1
      }
      if (previous != "sudo stage=review event=helper-exit status=0" || helper == "") {
        print "the module logged approval without the helper exit that must precede it"
        exit 1
      }
      print helper
    }
  '
}

# Reads one helper's messages on stdin; $1 is the PID of the verification
# sudo. Prints how the helper approved (mac, phone or delegation), or a reason
# and fails.
csec_sudo_helper_approval() {
  /usr/bin/awk -v parent="$1" '
    NF == 0 { next }
    $0 == "event=started parent=" parent { started++ }
    $0 == "event=delegation decision=approved" { route = "delegation" }
    /^event=outcome result=approved surface=(mac|phone) status=0$/ {
      route = substr($3, 9)
    }
    /^event=rejected / { rejected = 1 }
    { last = $0; lines++ }
    END {
      if (!lines) { print "the review helper logged nothing"; exit 1 }
      if (started != 1) { print "the review helper was not started by this sudo"; exit 1 }
      if (rejected) { print "the review helper refused the review"; exit 1 }
      if (route == "") { print "the review helper did not record an approval"; exit 1 }
      if (last != "event=exit status=0") {
        print "the review helper did not exit 0 last (last: " last ")"
        exit 1
      }
      print route
    }
  '
}

# Whether the installed helper at $3 approved the sudo with PID $2 that ran
# after $1. Prints the approval route, or the reason it was not shown.
csec_sudo_verified_approval() {
  local module_trail helper helper_trail
  if ! module_trail="$(csec_sudo_module_trail "$1" "$2")"; then
    echo "the unified log could not be read"
    return 1
  fi
  if ! helper="$(printf '%s\n' "$module_trail" | csec_sudo_approving_helper)"; then
    printf '%s\n' "$helper"
    return 1
  fi
  if ! helper_trail="$(csec_sudo_helper_trail "$1" "$helper" "$3")"; then
    echo "the unified log could not be read"
    return 1
  fi
  printf '%s\n' "$helper_trail" | csec_sudo_helper_approval "$2"
}

# The helper PIDs one sudo's module messages (stdin) name, for the trail.
csec_sudo_named_helpers() {
  /usr/bin/awk '/^sudo stage=review event=signature-check-started pid=[1-9][0-9]*$/ { print substr($NF, 5) }'
}
