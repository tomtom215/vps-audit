#!/usr/bin/env bash
# shellcheck shell=bash
#
# Real-state scenarios, run INSIDE a disposable container as root (see
# tests/matrix.sh). Unlike the unit tests these use real tools and real kernel
# state - nft rules, a mounted filesystem, /etc/passwd entries, sshd -T - and
# check the verdict the audit reaches through its JSON report.
#
# Needs: jq, and a container started with --privileged (nft, mount).

set -u
AUDIT="${AUDIT:-/src/vps-audit.sh}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

failures=0
pass() { printf 'ok    %s\n' "$1"; }
fail() { printf 'FAIL  %s\n      %s\n' "$1" "$2"; failures=$((failures + 1)); }
skip() { printf 'skip  %s (%s)\n' "$1" "$2"; }

# audit CATEGORIES -> path of the JSON report
audit() {
    local dir
    dir="$(mktemp -d "$WORK/run.XXXXXX")"
    "$AUDIT" --checks "$1" -f json -q --no-network --no-suid -o "$dir" >/dev/null 2>"$dir/stderr"
    ls "$dir"/vps-audit-report-*.json
}
audit_with_suid() {
    local dir
    dir="$(mktemp -d "$WORK/run.XXXXXX")"
    "$AUDIT" --checks "$1" -f json -q --no-network -o "$dir" >/dev/null 2>"$dir/stderr"
    ls "$dir"/vps-audit-report-*.json
}
# verdict REPORT "Check Name Prefix" -> "STATUS|critical|message"
verdict() {
    jq -r --arg n "$2" '.checks[] | select(.name | startswith($n)) | "\(.status)|\(.critical)|\(.message)"' "$1" | head -n 1
}

command -v jq >/dev/null 2>&1 || { echo "jq is required"; exit 77; }

# --- firewall: real nftables rules ------------------------------------------
if command -v nft >/dev/null 2>&1 && nft list ruleset >/dev/null 2>&1; then
    nft flush ruleset
    v="$(verdict "$(audit firewall)" "Firewall Status")"
    [[ "$v" == FAIL\|true\|* ]] && pass "firewall: empty ruleset is a critical FAIL" ||
        fail "firewall: empty ruleset must be a critical FAIL" "got: $v"

    nft add table inet filter
    nft add chain inet filter input '{ type filter hook input priority 0; policy accept; }'
    nft add rule inet filter input tcp dport 22 accept
    v="$(verdict "$(audit firewall)" "Firewall Status")"
    [[ "$v" == FAIL\|* ]] && pass "firewall: input hook with policy accept is not protection" ||
        fail "firewall: policy accept must not pass" "got: $v"

    nft flush ruleset
    nft add table inet filter
    nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'
    nft add rule inet filter input ct state established,related accept
    nft add rule inet filter input tcp dport 22 accept
    v="$(verdict "$(audit firewall)" "Firewall Status")"
    [[ "$v" == PASS\|* ]] && pass "firewall: real default-deny nftables policy passes" ||
        fail "firewall: policy drop must pass" "got: $v"
    nft flush ruleset
else
    skip "firewall scenarios" "nft unavailable or no CAP_NET_ADMIN"
fi

# --- users: empty password on a login account ----------------------------------
cp /etc/passwd "$WORK/passwd.bak"
cp /etc/shadow "$WORK/shadow.bak"
echo 'ghost:x:4242:4242::/home/ghost:/bin/bash' >>/etc/passwd
echo 'ghost::19000:0:99999:7:::' >>/etc/shadow
v="$(verdict "$(audit users)" "User Accounts")"
[[ "$v" == FAIL\|*ghost* ]] && pass "users: empty password on a login account is reported by name" ||
    fail "users: empty password must FAIL and name 'ghost'" "got: $v"
cp "$WORK/passwd.bak" /etc/passwd
cp "$WORK/shadow.bak" /etc/shadow

# --- suid: a planted binary on a separate mount ----------------------------------
mkdir -p /srv/vol
if mount -t tmpfs tmpfs /srv/vol 2>/dev/null; then
    cp /bin/true /srv/vol/planted-suid
    chmod 4755 /srv/vol/planted-suid
    r="$(audit_with_suid suid)"
    v="$(verdict "$r" "SUID Files")"
    # The console message shows only the first few names; the text report has all.
    if [[ "$v" == WARN\|* ]] && grep -q 'planted-suid' "$r" "${r%.json}.txt"; then
        pass "suid: a SUID file on a separate mount is found (find / -xdev missed these)"
    else
        fail "suid: planted SUID file on /srv/vol must be reported" "got: $v"
    fi
    umount /srv/vol
else
    skip "suid separate-mount scenario" "cannot mount tmpfs (container not privileged)"
fi

# --- ssh: real sshd -T ---------------------------------------------------------
if command -v sshd >/dev/null 2>&1 || [[ -x /usr/sbin/sshd ]]; then
    mkdir -p /etc/ssh /run/sshd
    command -v ssh-keygen >/dev/null 2>&1 && ssh-keygen -A >/dev/null 2>&1
    cp -f /etc/ssh/sshd_config "$WORK/sshd_config.bak" 2>/dev/null
    printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' >/etc/ssh/sshd_config
    r="$(audit ssh)"
    v="$(verdict "$r" "SSH Root Login")"
    [[ "$v" == FAIL\|true\|* ]] && pass "ssh: PermitRootLogin yes is a critical FAIL" ||
        fail "ssh: PermitRootLogin yes must be a critical FAIL" "got: $v"
    printf 'PermitRootLogin no\nPasswordAuthentication no\n' >/etc/ssh/sshd_config
    r="$(audit ssh)"
    v="$(verdict "$r" "SSH Root Login")"
    [[ "$v" == PASS\|* ]] && pass "ssh: PermitRootLogin no passes" || fail "ssh: PermitRootLogin no must pass" "got: $v"
    v="$(verdict "$r" "SSH Password Auth")"
    [[ "$v" == PASS\|* ]] && pass "ssh: PasswordAuthentication no passes" || fail "ssh: PasswordAuthentication no must pass" "got: $v"
    [[ -f "$WORK/sshd_config.bak" ]] && cp -f "$WORK/sshd_config.bak" /etc/ssh/sshd_config
else
    skip "ssh scenarios" "sshd not installed"
fi

echo
if [[ $failures -gt 0 ]]; then
    echo "$failures scenario(s) failed"
    exit 1
fi
echo "all scenarios passed"
