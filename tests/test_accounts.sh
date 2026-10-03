#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2016,SC2034,SC2154
#
# Legacy services, home directories, auditd. All three were false positives on
# stock distribution images, found by the distro matrix.

# --- legacy plaintext services ---------------------------------------------------
# Arch's inetutils (installed to provide `hostname`) ships telnetd, rshd, rlogind
# and talkd. Binaries on disk are not services: the check reported
# "FAIL - Multiple legacy plaintext service daemons present".

legacy_case() { # ss-lines (may be empty) daemons-present...
    hide_system_commands
    SS_OUT="$1"
    stub ss 'printf "%s\n" "$SS_OUT"'
    local d
    for d in "${@:2}"; do stub "$d" 'return 0'; done
    OS_INFO[pkg_manager]=none
    record_checks
    check_legacy_services
}

test_legacy_binaries_without_a_listener_are_info() {
    legacy_case 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))' telnetd rshd rlogind talkd || return 1
    assert_eq INFO "$RESULT_STATUS" "$RESULT_MSG" || return 1
    assert_contains "$RESULT_MSG" "nothing is listening" || return 1
}

test_legacy_service_listening_publicly_is_a_critical_fail() {
    legacy_case 'tcp LISTEN 0 128 0.0.0.0:23 0.0.0.0:* users:(("in.telnetd",pid=1,fd=3))' telnetd || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
    assert_eq true "$RESULT_CRIT" || return 1
    assert_contains "$RESULT_MSG" "telnet" || return 1
    assert_contains "$RESULT_MSG" "23" || return 1
}

test_legacy_tftp_on_udp_69_is_detected() {
    legacy_case 'udp UNCONN 0 0 0.0.0.0:69 0.0.0.0:* users:(("in.tftpd",pid=1,fd=3))' || return 1
    assert_eq FAIL "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_legacy_service_on_loopback_only_is_a_warning() {
    legacy_case 'tcp LISTEN 0 128 127.0.0.1:23 0.0.0.0:* users:(("in.telnetd",pid=1,fd=3))' || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
}

test_legacy_nothing_present_passes() {
    legacy_case 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))' || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_legacy_without_ss_falls_back_to_installed_daemons() {
    hide_system_commands
    stub telnetd 'return 0'
    OS_INFO[pkg_manager]=none
    record_checks
    check_legacy_services
    assert_eq WARN "$RESULT_STATUS" "cannot see listeners, so an installed daemon is a warning: $RESULT_MSG" || return 1
}

# --- home directory permissions -----------------------------------------------------------

home_case() { # passwd-lines...
    local d
    d="$(make_tmp)" || return 1
    printf '%s\n' "$@" >"$d/passwd"
    PASSWD_FILE="$d/passwd"
    LOGIN_DEFS=/nonexistent
    detect_tool_versions
    record_checks
}

# openSUSE's `nobody` (uid 65534, nologin) has a world-readable home; the old
# check flagged it without naming it.
test_home_dirs_ignore_accounts_without_a_login_shell() {
    local d
    d="$(make_tmp)" || return 1
    mkdir -p "$d/nobody" "$d/alice"
    chmod 755 "$d/nobody"
    chmod 700 "$d/alice"
    home_case "nobody:x:65534:65534:nobody:$d/nobody:/sbin/nologin" "alice:x:1000:1000::$d/alice:/bin/bash" || return 1
    check_home_directory_permissions
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_home_dirs_name_the_offending_accounts() {
    local d
    d="$(make_tmp)" || return 1
    mkdir -p "$d/alice" "$d/bob"
    chmod 755 "$d/alice"
    chmod 777 "$d/bob"
    home_case "alice:x:1000:1000::$d/alice:/bin/bash" "bob:x:1001:1001::$d/bob:/bin/bash" || return 1
    check_home_directory_permissions
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "alice" || return 1
    assert_contains "$RESULT_MSG" "bob" || return 1
    assert_contains "$RESULT_REC" "chmod 750" || return 1
}

# Ubuntu 21.04+ creates homes 0750; that must not be flagged.
test_home_dirs_750_is_fine() {
    local d
    d="$(make_tmp)" || return 1
    mkdir -p "$d/alice"
    chmod 750 "$d/alice"
    home_case "alice:x:1000:1000::$d/alice:/bin/bash" || return 1
    check_home_directory_permissions
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# --- auditd ------------------------------------------------------------------------------------

# On Arch the `audit` package is pulled in as a dependency of core libraries,
# so "installed but not running" is not a decision anyone made.
test_audit_installed_but_not_running_is_info() {
    hide_system_commands
    OS_INFO[pkg_manager]=apt
    OS_INFO[service_manager]=systemd
    stub dpkg 'printf "ii  auditd\n"'
    stub systemctl 'return 1'
    record_checks
    check_audit_system
    assert_eq INFO "$RESULT_STATUS" || return 1
}

test_audit_running_without_rules_still_warns() {
    hide_system_commands
    OS_INFO[pkg_manager]=apt
    OS_INFO[service_manager]=systemd
    stub dpkg 'printf "ii  auditd\n"'
    stub systemctl '[[ "$1" == is-active ]]'
    stub auditctl 'echo "No rules"'
    record_checks
    check_audit_system
    assert_eq WARN "$RESULT_STATUS" || return 1
}
