#!/usr/bin/env bash
# shellcheck shell=bash
#
# Firewall detection. The fixtures under tests/fixtures/firewall/ are real
# `nft list ruleset` / `iptables -S INPUT` output captured from ubuntu:24.04
# (nftables 1.0.9, iptables 1.8.10) and from a Docker host.
#
# Invariant under test: a host counts as firewalled only if inbound traffic is
# default-denied (policy DROP, or an unconditional trailing drop/reject on the
# input hook). Merely *having* chains or rules (Docker, fail2ban) is not enough.

FIXTURES="$TESTS_DIR/fixtures/firewall"

# Run check_firewall_status with only the given firewall tools visible. Tools
# are stubbed to replay fixture files; no real firewall tool can leak in.
# usage: firewall_case NFT_FIXTURE|- IPT_FIXTURE|- [ufw_status] [firewalld_state]
firewall_case() {
    local nft_fx="$1" ipt_fx="$2" ufw_out="${3:-}" fwd_out="${4:-}"
    hide_system_commands
    record_checks
    if [[ "$nft_fx" != "-" ]]; then
        NFT_FX="$FIXTURES/$nft_fx"
        stub nft 'cat "$NFT_FX"'
    fi
    if [[ "$ipt_fx" != "-" ]]; then
        IPT_FX="$FIXTURES/$ipt_fx"
        stub iptables 'cat "$IPT_FX"'
    fi
    if [[ -n "$ufw_out" ]]; then
        UFW_OUT="$ufw_out"
        stub ufw 'echo "$UFW_OUT"'
    fi
    if [[ -n "$fwd_out" ]]; then
        FWD_OUT="$fwd_out"
        stub firewall-cmd 'echo "$FWD_OUT"'
    fi
    check_firewall_status
}

test_firewall_none_installed_is_critical_fail() {
    firewall_case - - || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
    assert_eq true "$RESULT_CRIT" "must be flagged critical" || return 1
    assert_contains "$RESULT_MSG" "No host firewall" || return 1
}

test_firewall_ufw_active_passes() {
    firewall_case - - "Status: active" || return 1
    assert_eq PASS "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_NAME" "UFW" || return 1
}

test_firewall_ufw_inactive_fails() {
    firewall_case - - "Status: inactive" || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
}

test_firewall_firewalld_running_passes() {
    firewall_case - - "" "running" || return 1
    assert_eq PASS "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_NAME" "firewalld" || return 1
}

test_firewall_nft_policy_drop_passes() {
    firewall_case nft-policy-drop.txt - || return 1
    assert_eq PASS "$RESULT_STATUS" || return 1
}

test_firewall_nft_catchall_drop_passes() {
    firewall_case nft-catchall-drop.txt - || return 1
    assert_eq PASS "$RESULT_STATUS" || return 1
}

test_firewall_nft_empty_ruleset_fails() {
    firewall_case nft-empty.txt - || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
}

# Regression: Docker alone creates nft chains; the old check counted the word
# "chain" and reported "nftables is active and protecting the system".
test_firewall_nft_docker_chains_only_fails() {
    firewall_case nft-docker-only.txt ipt-docker-only.txt || return 1
    assert_eq FAIL "$RESULT_STATUS" "docker chains are not a firewall" || return 1
    assert_eq true "$RESULT_CRIT" || return 1
}

# Regression: fail2ban's input-hook chain only rejects banned addresses; the
# host is otherwise open.
test_firewall_nft_fail2ban_only_fails() {
    firewall_case nft-fail2ban-only.txt - || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
}

test_firewall_iptables_policy_drop_passes() {
    firewall_case - ipt-policy-drop.txt || return 1
    assert_eq PASS "$RESULT_STATUS" || return 1
}

test_firewall_iptables_catchall_drop_passes() {
    firewall_case - ipt-catchall-drop.txt || return 1
    assert_eq PASS "$RESULT_STATUS" || return 1
}

test_firewall_iptables_empty_fails() {
    firewall_case - ipt-empty.txt || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
}

# Regression: an INPUT chain whose only rule is a jump into fail2ban's chain
# (policy ACCEPT) was counted as "has rules => active".
test_firewall_iptables_fail2ban_only_fails() {
    firewall_case - ipt-fail2ban-only.txt || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
}

test_firewall_failure_mentions_provider_firewalls() {
    firewall_case - ipt-empty.txt || return 1
    assert_contains "$RESULT_REC" "provider" "advise that cloud-provider firewalls are invisible to the script" || return 1
}
