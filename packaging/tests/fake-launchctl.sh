#!/bin/bash
set -eu

state_directory="${CSEC_FAKE_LAUNCHCTL_STATE:?set CSEC_FAKE_LAUNCHCTL_STATE}"
state_file="$state_directory/state"
remaining_file="$state_directory/removal-polls"
bootstrap_file="$state_directory/bootstrap-attempts"
kickstart_file="$state_directory/kickstarts"

read_count() {
  local file="$1"
  if [ -f "$file" ]; then
    /bin/cat "$file"
  else
    echo 0
  fi
}

increment() {
  local file="$1"
  local count
  count="$(read_count "$file")"
  echo $((count + 1)) >"$file"
}

command="${1:-}"
case "$command" in
  bootout)
    echo removing >"$state_file"
    echo 2 >"$remaining_file"
    ;;
  print)
    state="$(/bin/cat "$state_file")"
    case "$state" in
      loaded) exit 0 ;;
      removing)
        remaining="$(/bin/cat "$remaining_file")"
        if [ "$remaining" -gt 0 ]; then
          echo $((remaining - 1)) >"$remaining_file"
          exit 0
        fi
        echo unloaded-transient >"$state_file"
        exit 1
        ;;
      unloaded | unloaded-transient) exit 1 ;;
      *) exit 2 ;;
    esac
    ;;
  bootstrap)
    increment "$bootstrap_file"
    state="$(/bin/cat "$state_file")"
    case "$state" in
      unloaded-transient)
        # Model the short interval where print no longer sees the old job but
        # launchd still reports its removal transaction as in progress.
        echo unloaded >"$state_file"
        echo "Bootstrap failed: 5: Input/output error" >&2
        exit 5
        ;;
      unloaded)
        echo loaded >"$state_file"
        ;;
      *) exit 5 ;;
    esac
    ;;
  kickstart)
    [ "$(/bin/cat "$state_file")" = loaded ]
    increment "$kickstart_file"
    ;;
  *) exit 64 ;;
esac
