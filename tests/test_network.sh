#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2016,SC2034,SC2154
#
# Listening ports and exposed services, driven by `ss -tulnp` output. The base
# fixture is real output (iproute2 on Ubuntu 24.04 with sshd and three netcat
# listeners); a few lines in the same format are appended for cases a bare
# container cannot produce.

SS_FIXTURE="$TESTS_DIR/fixtures/network/ss-tulnp-ubuntu.txt"

ports_case() { # extra ss lines...
    hide_system_commands
    SS_OUT="$(cat "$SS_FIXTURE")"$'\n'"$(printf '%s\n' "$@")"
    stub ss 'printf "%s\n" "$SS_OUT"'
    record_checks
}

test_ports_names_the_public_listeners_with_their_process() {
    ports_case || return 1
    check_open_ports
    assert_contains "$RESULT_MSG" "22/sshd" || return 1
    assert_contains "$RESULT_MSG" "8080/nc" || return 1
    assert_not_contains "$RESULT_MSG" "6379" "loopback-only ports are not public" || return 1
}

test_ports_typical_web_server_passes() {
    # ssh + http + https is the normal shape of a VPS and must not warn.
    ports_case 'tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*    users:(("nginx",pid=9,fd=6))' \
        'tcp   LISTEN 0      511             [::]:443       [::]:*    users:(("nginx",pid=9,fd=7))' || return 1
    SS_OUT="$(grep -v ':8080\|:5000' <<<"$SS_OUT")"
    check_open_ports
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# DHCP client sockets are bound to the interface address (ss prints
# 203.0.113.10%eth0:68) and are not a service anyone connects to.
test_ports_dhcp_client_socket_is_ignored() {
    ports_case 'udp   UNCONN 0      0      203.0.113.10%eth0:68        0.0.0.0:*    users:(("systemd-network",pid=3,fd=22))' || return 1
    check_open_ports
    assert_not_contains "$RESULT_MSG" ":68" || return 1
    assert_not_contains "$RESULT_MSG" "68/" || return 1
}

test_ports_many_public_listeners_warn_then_fail() {
    local i lines=()
    for i in {9000..9003}; do
        lines+=("tcp   LISTEN 0      1          0.0.0.0:$i        0.0.0.0:*    users:((\"app\",pid=$i,fd=3))")
    done
    ports_case "${lines[@]}" || return 1
    check_open_ports
    assert_eq WARN "$RESULT_STATUS" "$RESULT_MSG" || return 1
    for i in {9004..9011}; do
        lines+=("tcp   LISTEN 0      1          0.0.0.0:$i        0.0.0.0:*    users:((\"app\",pid=$i,fd=3))")
    done
    ports_case "${lines[@]}" || return 1
    check_open_ports
    assert_eq FAIL "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# Found by the distro matrix on every image: with NO public listener, printf
# of an empty array still emitted one empty line, which became an empty array
# subscript ("bad array subscript") and a message ending "Public: 0 (/)".
test_ports_no_public_listeners_is_clean() {
    hide_system_commands
    SS_OUT=$'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\ntcp LISTEN 0 128 127.0.0.1:6379 0.0.0.0:* users:(("redis",pid=1,fd=3))'
    stub ss 'printf "%s\n" "$SS_OUT"'
    record_checks
    local err
    err="$(check_open_ports 2>&1 >/dev/null)"
    check_open_ports 2>/dev/null
    assert_eq "" "$err" "no bash errors on stderr" || return 1
    assert_eq PASS "$RESULT_STATUS" || return 1
    assert_eq "Public: 0; local-only: 1" "$RESULT_MSG" || return 1
}

test_ports_without_ss_or_netstat_is_unknown() {
    hide_system_commands
    record_checks
    check_open_ports
    assert_eq WARN "$RESULT_STATUS" || return 1
}

# --- exposed backend services ----------------------------------------------------

exposed_case() {
    hide_system_commands
    SS_OUT="$(printf '%s\n' "$@")"
    stub ss 'printf "%s\n" "$SS_OUT"'
    record_checks
    check_exposed_services
}

test_exposed_database_on_wildcard_is_flagged() {
    exposed_case 'tcp LISTEN 0 128 0.0.0.0:3306 0.0.0.0:* users:(("mysqld",pid=1,fd=3))' || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "MySQL" || return 1
}

# Regression: only 0.0.0.0/*/[::] were matched, so a database bound to the
# server's own public address looked safe.
test_exposed_database_on_a_specific_public_address_is_flagged() {
    exposed_case 'tcp LISTEN 0 128 203.0.113.5:3306 0.0.0.0:* users:(("mysqld",pid=1,fd=3))' \
        'tcp LISTEN 0 128 [2001:db8::5]:6379 [::]:* users:(("redis",pid=2,fd=3))' || return 1
    assert_ne PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
    assert_contains "$RESULT_MSG" "MySQL" || return 1
    assert_contains "$RESULT_MSG" "Redis" || return 1
}

test_exposed_database_on_loopback_or_private_is_fine() {
    exposed_case 'tcp LISTEN 0 128 127.0.0.1:3306 0.0.0.0:* users:(("mysqld",pid=1,fd=3))' \
        'tcp LISTEN 0 128 10.0.0.5:5432 0.0.0.0:* users:(("postgres",pid=2,fd=3))' || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_exposed_unauthenticated_docker_api_is_flagged() {
    exposed_case 'tcp LISTEN 0 128 0.0.0.0:2375 0.0.0.0:* users:(("dockerd",pid=1,fd=3))' || return 1
    assert_ne PASS "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "Docker" || return 1
}

test_exposed_port_prefix_does_not_match_longer_ports() {
    exposed_case 'tcp LISTEN 0 128 0.0.0.0:23799 0.0.0.0:* users:(("x",pid=1,fd=3))' || return 1
    assert_eq PASS "$RESULT_STATUS" "2379 must not match 23799: $RESULT_MSG" || return 1
}

# --- failed logins -----------------------------------------------------------------
# With password auth off, attackers' attempts log as "Invalid user" and
# "Connection closed by authenticating user ... [preauth]" - never "Failed
# password" - so the old count stayed at 0 under a live brute-force.

logins_case() { # journal lines...
    OS_INFO[service_manager]=systemd
    hide_system_commands
    JOURNAL="$(printf '%s\n' "$@")"
    stub journalctl '[[ "$1" == "-n0" ]] && return 0; printf "%s\n" "$JOURNAL"'
    record_checks
    check_failed_logins
}

test_failed_logins_count_invalid_user_and_preauth_closes() {
    logins_case \
        'sshd[1]: Invalid user admin from 198.51.100.7 port 4000' \
        'sshd[1]: Connection closed by invalid user admin 198.51.100.7 port 4000 [preauth]' \
        'sshd[2]: Connection closed by authenticating user root 198.51.100.7 port 4001 [preauth]' \
        'sshd[3]: Failed password for root from 198.51.100.7 port 4002 ssh2' || return 1
    assert_contains "$RESULT_MSG" "3 failed login" "Invalid user + authenticating-user close + Failed password" || return 1
}

test_failed_logins_quiet_log_passes() {
    logins_case 'sshd[1]: Accepted publickey for alice from 198.51.100.9 port 5000 ssh2' || return 1
    assert_eq PASS "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "0 failed login" || return 1
}

test_failed_logins_threshold_bands() {
    local i lines=()
    for i in {1..12}; do lines+=("sshd[$i]: Failed password for root from 198.51.100.7 port $i ssh2"); done
    logins_case "${lines[@]}" || return 1
    assert_eq WARN "$RESULT_STATUS" "12 >= warn(10): $RESULT_MSG" || return 1
}

# `hostname -f` resolves the machine's own name through DNS when it is not in
# /etc/hosts (traced with strace: connect() to the resolver on port 53), so
# --no-network must not call it. Observed as the one remaining network access.
hostname_case() { # skip_network
    hide_system_commands
    CONFIG[skip_network]="$1"
    HOSTNAME_CALLS="$(make_tmp)/calls"
    : >"$HOSTNAME_CALLS"
    stub_bin hostname 'echo "$*" >>"$HOSTNAME_CALLS"; if [ "$1" = "-f" ]; then echo server.example.com; else echo server; fi'
    export HOSTNAME_CALLS
}

test_no_network_never_asks_for_the_fqdn() {
    hostname_case true || return 1
    assert_eq server "$(get_display_hostname)" || return 1
    assert_not_contains "$(cat "$HOSTNAME_CALLS")" "-f" "hostname -f can trigger a DNS query" || return 1
}

test_hostname_is_fully_qualified_when_network_is_allowed() {
    hostname_case false || return 1
    assert_eq server.example.com "$(get_display_hostname)" || return 1
}

test_hostname_falls_back_to_the_short_name_when_the_fqdn_lookup_fails() {
    hostname_case false || return 1
    stub_bin hostname 'if [ "$1" = "-f" ]; then exit 1; else echo server; fi'
    assert_eq server "$(get_display_hostname)" || return 1
}

test_hostname_unknown_when_nothing_answers() {
    hostname_case false || return 1
    stub_bin hostname 'exit 1'
    assert_eq unknown "$(get_display_hostname)" || return 1
}
