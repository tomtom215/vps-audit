#!/usr/bin/env bash
# shellcheck shell=bash
#
# Runs inside a container (see tests/matrix.sh): environment report, unit
# suites, real-state scenarios, then one full audit whose JSON and streams the
# host validates. Everything is written to /out.

set -u
OUT="${OUT:-/out}"
SRC="${SRC:-/src}"

{
    echo "bash:   $BASH_VERSION"
    echo "kernel: $(uname -r)"
    # shellcheck disable=SC1091
    . /etc/os-release && echo "distro: ${PRETTY_NAME:-$ID}"
    for t in sshd nft iptables ufw firewall-cmd systemctl ss jq; do
        printf '%-14s %s\n' "$t:" "$(command -v "$t" 2>/dev/null || echo MISSING)"
    done
    # shellcheck disable=SC2012  # this records the version of ls itself
    echo "ls:     $(ls --version 2>&1 | head -1)"
    echo "stat:   $(stat --version 2>&1 | head -1)"
} >"$OUT/env.txt" 2>&1

"$SRC/tests/run.sh" >"$OUT/tests.log" 2>&1
echo $? >"$OUT/tests.exit"

"$SRC/tests/container/scenarios.sh" >"$OUT/scenarios.log" 2>&1
echo $? >"$OUT/scenarios.exit"

"$SRC/vps-audit.sh" -f both -o "$OUT" --no-network >"$OUT/audit.stdout" 2>"$OUT/audit.stderr"
echo $? >"$OUT/audit.exit"
