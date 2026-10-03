#!/usr/bin/env bash
# shellcheck shell=bash
#
# Minimal test framework for vps-audit (no external dependencies).
#
# A suite file defines functions named test_*. The runner (tests/run.sh)
# sources each suite and runs every test_* function in its own subshell so a
# failing assertion, `exit`, or global mutation in one test cannot leak into
# the next. A test passes when its function returns 0.
#
# Bash 4.0 compatible on purpose (no `declare -g`, `local -n`, `[[ -v ]]`).

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$TESTS_DIR")"
AUDIT_SCRIPT="${AUDIT_SCRIPT:-$REPO_DIR/vps-audit.sh}"

# --- assertions --------------------------------------------------------------
# Each prints a diagnostic and returns 1 on failure. Tests chain them with
# `|| return 1` (the runner does not use `set -e`, so this is explicit).

fail() {
    printf '    %s\n' "$*" >&2
    return 1
}

assert_eq() { # expected actual [message]
    [[ "$1" == "$2" ]] && return 0
    fail "${3:-assert_eq}: expected [$1] got [$2]"
}

assert_ne() { # unexpected actual [message]
    [[ "$1" != "$2" ]] && return 0
    fail "${3:-assert_ne}: value must not be [$1]"
}

assert_contains() { # haystack needle [message]
    [[ "$1" == *"$2"* ]] && return 0
    fail "${3:-assert_contains}: [$2] not found in [${1:0:300}]"
}

assert_not_contains() { # haystack needle [message]
    [[ "$1" != *"$2"* ]] || {
        fail "${3:-assert_not_contains}: unexpected [$2] in [${1:0:300}]"
        return 1
    }
}

assert_status() { # expected_status actual_status [message]
    [[ "$1" == "$2" ]] && return 0
    fail "${3:-assert_status}: expected exit $1 got $2"
}

assert_match() { # string ERE [message]
    [[ "$1" =~ $2 ]] && return 0
    fail "${3:-assert_match}: [${1:0:200}] does not match /$2/"
}

# --- fixtures ----------------------------------------------------------------

# Per-test scratch directory, removed by the runner after the test.
# Directories are recorded in $TEST_TMPLIST (set by the runner) because this is
# called inside $(...) subshells; the runner deletes them after every test, pass
# or fail, so a failing test cannot leave world-writable fixtures in /tmp.
make_tmp() {
    local d
    d="$(mktemp -d "${TMPDIR:-/tmp}/vps-audit-test.XXXXXX")" || return 1
    [[ -n "${TEST_TMPLIST:-}" ]] && printf '%s\n' "$d" >>"$TEST_TMPLIST"
    printf '%s\n' "$d"
}

# The runner sources the script under test at the top level of every test's
# subshell (see tests/run.sh), so its associative arrays and readonly state are
# real globals and are reset for each test. Do NOT source it from inside a
# function: `declare -A` there creates function-local variables that vanish on
# return. init_colors is not called by the runner; tests that exercise colour
# call it themselves (it makes the colour variables readonly).

# Restrict PATH to a scratch directory holding symlinks to basic utilities only,
# so tools like ufw/nft/iptables/systemctl that happen to exist on the machine
# running the tests can never leak into a test. Call after the script is sourced (it
# prepends system directories to PATH).
hide_system_commands() {
    local dir util real
    dir="$(make_tmp)" || return 1
    for util in awk grep sed cut tr head tail sort uniq wc cat date stat find ls uname \
        hostname id mktemp rm mv chmod mkdir dirname basename tee sleep xargs od \
        readlink df nproc timeout comm touch ln cp env tput stty; do
        real="$(command -v "$util" 2>/dev/null)" || continue
        [[ "$real" == /* ]] && ln -s "$real" "$dir/$util"
    done
    PATH="$dir"
    HIDE_DIR="$dir"
    # shellcheck disable=SC2064  # expand $dir now: it is a fixed scratch path
    trap "rm -rf '$dir'" EXIT
    # The script caches command lookups; drop anything cached before the swap.
    CMD_CACHE=()
}

# Like `stub`, but writes a real executable into the hidden-command directory,
# for code paths that run the command through another program (e.g.
# `timeout 5 docker ...`), which cannot call shell functions.
# Usage (after hide_system_commands): stub_bin name 'shell body'
stub_bin() {
    [[ -n "${HIDE_DIR:-}" ]] || { echo "stub_bin needs hide_system_commands first" >&2; return 1; }
    printf '#!/bin/sh\n%s\n' "$2" >"$HIDE_DIR/$1"
    chmod +x "$HIDE_DIR/$1"
    CMD_CACHE=()
}

# Replace check_security with a recorder so a test can assert on the verdict a
# check function reached (status / message / recommendation / critical flag)
# without parsing console output.
record_checks() {
    RESULT_COUNT=0
    RESULT_NAME="" RESULT_STATUS="" RESULT_MSG="" RESULT_REC="" RESULT_CRIT=""
    check_security() {
        RESULT_COUNT=$((RESULT_COUNT + 1))
        RESULT_NAME="$1" RESULT_STATUS="$2" RESULT_MSG="$3" RESULT_REC="${4:-}" RESULT_CRIT="${5:-false}"
    }
}

# Define a shell function that shadows an external command for the duration of
# the (sub)shell. Usage: stub name 'body using $1 $2 ...'
stub() {
    eval "$1() { $2 ; }"
}

# Run the audit script as a user would, capturing combined output + status.
# Sets OUT and STATUS. Extra args are passed to the script.
run_audit() {
    OUT="$("$AUDIT_SCRIPT" "$@" 2>&1)"
    STATUS=$?
}
