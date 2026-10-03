#!/usr/bin/env bash
# shellcheck shell=bash
#
# Pure helper functions and the data-producing primitives (update counting,
# sshd config resolution, JSON output). Commands are stubbed with shell
# functions; nothing here touches the real system.

# --- numeric helpers ---------------------------------------------------------

test_is_numeric() {
    local v
    for v in 0 7 123 99999; do
        is_numeric "$v" || fail "is_numeric [$v] should succeed"
    done
    for v in "" " " abc 12.3 -1 "1 2" "1;2" '$(id)'; do
        is_numeric "$v" && fail "is_numeric [$v] should fail"
    done
    return 0
}

test_is_integer_accepts_negatives_for_pwquality_credits() {
    local v
    for v in 0 -1 -100 42; do
        is_integer "$v" || fail "is_integer [$v] should succeed"
    done
    for v in "" abc 1.5 --1 "- 1"; do
        is_integer "$v" && fail "is_integer [$v] should fail"
    done
    return 0
}

test_sanitize_int() {
    assert_eq 0 "$(sanitize_int '')" || return 1
    assert_eq 12 "$(sanitize_int '  12  ')" || return 1
    assert_eq 8 "$(sanitize_int '08')" "08 must be base 10, not octal" || return 1
    assert_eq 0 "$(sanitize_int abc)" || return 1
    # The historical "0\n0" produced by `grep -c ... || echo 0` collapses to 00 -> 0.
    assert_eq 0 "$(sanitize_int "$(printf '0\n0')")" || return 1
}

test_count_lines_is_always_one_clean_integer() {
    assert_eq 0 "$(printf '' | count_lines)" || return 1
    assert_eq 3 "$(printf 'a\nb\nc\n' | count_lines)" || return 1
    assert_eq 1 "$(printf 'x' | count_lines)" "no trailing newline" || return 1
    assert_eq 0 "$(printf 'a\n' | grep zzz | count_lines)" "grep with no match" || return 1
}

test_bytes_to_human() {
    assert_eq 0B "$(bytes_to_human 0)" || return 1
    assert_eq 512B "$(bytes_to_human 512)" || return 1
    assert_eq 1.0K "$(bytes_to_human 1024)" || return 1
    assert_eq 1.5M "$(bytes_to_human 1572864)" || return 1
    assert_eq 2.0G "$(bytes_to_human 2147483648)" || return 1
    assert_eq "?" "$(bytes_to_human abc)" || return 1
}

# --- network classification --------------------------------------------------

test_classify_bind_scope() {
    local a
    for a in 0.0.0.0 '*' '::' 8.8.8.8 172.15.0.1 172.32.0.1 2001:db8::1; do
        assert_eq public "$(classify_bind_scope "$a")" "$a" || return 1
    done
    for a in 127.0.0.1 127.0.0.53 ::1 10.1.2.3 192.168.1.1 172.16.0.1 172.31.255.255 169.254.1.1 fe80::1 fd00::1; do
        assert_eq local "$(classify_bind_scope "$a")" "$a" || return 1
    done
}

# --- JSON --------------------------------------------------------------------

test_json_escape_basic_characters() {
    assert_eq '\"' "$(json_escape '"')" || return 1
    assert_eq '\\' "$(json_escape '\')" || return 1
    assert_eq 'a\tb' "$(json_escape "$(printf 'a\tb')")" || return 1
    assert_eq 'x\\\"y' "$(json_escape 'x\"y')" "backslash is escaped before the quote" || return 1
}

# Regression: control characters other than \n \r \t (ESC, BEL, NUL-adjacent
# bytes from log lines or config files) were passed through raw, producing
# JSON that jq and every strict parser reject.
test_json_report_is_valid_json_for_hostile_strings() {
    command -v jq >/dev/null 2>&1 || return 77
    local d nasty
    d="$(make_tmp)" || return 1
    nasty=$'quote" back\\ nl\n cr\r tab\t esc\033[31m bell\a unit\037 del\177 utf8 \xc3\xa9'
    CONFIG[output_format]=json
    REPORT_FILE="$d/report.txt"
    : >"$REPORT_FILE"
    init_json
    check_security "Name with \"quotes\"" PASS "$nasty" ""
    check_security "Second" FAIL "msg" "$nasty" true
    finalize_json >/dev/null
    jq -e . "$d/report.json" >/dev/null || fail "report is not valid JSON: $(head -c 300 "$d/report.json")" || return 1
    assert_eq "$nasty" "$(jq -j '.checks[0].message' "$d/report.json")" "string must round-trip exactly" || return 1
    rm -rf "$d"
}

test_json_report_structure_and_summary_arithmetic() {
    command -v jq >/dev/null 2>&1 || return 77
    local d
    d="$(make_tmp)" || return 1
    CONFIG[output_format]=json
    REPORT_FILE="$d/report.txt"
    : >"$REPORT_FILE"
    init_json
    should_run_check ssh
    check_security "A" PASS "ok" ""
    check_security "B" WARN "meh" "fix b"
    check_security "C" FAIL "bad" "fix c" true
    check_security "D" FAIL "bad" "fix d"
    finalize_json >/dev/null
    local j="$d/report.json"
    assert_eq 4 "$(jq '.checks | length' "$j")" || return 1
    assert_eq 4 "$(jq '.summary.total' "$j")" || return 1
    assert_eq "1 1 2 1 25" "$(jq -r '.summary | "\(.pass) \(.warn) \(.fail) \(.critical_fail) \(.score)"' "$j")" || return 1
    assert_eq "$VERSION" "$(jq -r '.version' "$j")" || return 1
    assert_eq 1 "$(jq -r '.schema_version' "$j")" || return 1
    assert_eq "true" "$(jq -r '.checks[2].critical' "$j")" || return 1
    assert_eq "false" "$(jq -r '.checks[3].critical' "$j")" || return 1
    assert_eq "ssh" "$(jq -r '.checks[0].category' "$j")" "category comes from the active should_run_check" || return 1
    assert_eq "null" "$(jq -r '.checks[0].priority' "$j")" "passing checks have no priority" || return 1
    assert_eq "critical" "$(jq -r '.checks[2].priority' "$j")" || return 1
    assert_eq "high" "$(jq -r '.checks[3].priority' "$j")" || return 1
    assert_eq "medium" "$(jq -r '.checks[1].priority' "$j")" || return 1
    rm -rf "$d"
}

test_json_report_with_no_checks_is_valid() {
    command -v jq >/dev/null 2>&1 || return 77
    local d
    d="$(make_tmp)" || return 1
    CONFIG[output_format]=json
    REPORT_FILE="$d/report.txt"
    : >"$REPORT_FILE"
    init_json
    finalize_json >/dev/null
    assert_eq 0 "$(jq '.checks | length' "$d/report.json")" || return 1
    rm -rf "$d"
}

# --- update counting ---------------------------------------------------------
# Regression for the v2.4.0 fix: `grep -c ... || echo 0` yielded "0\n0" and a
# fully patched host was reported as "unable to determine update status".

updates_case() { # pkg_manager
    OS_INFO[pkg_manager]="$1"
    hide_system_commands
}

test_update_count_apt() {
    updates_case apt
    stub apt-get 'printf "Inst a [1] (2 Ubuntu:24.04/noble-security)\nInst b [1] (2 Ubuntu:24.04/noble-updates)\nConf a\n"'
    assert_eq 2 "$(get_update_count)" || return 1
    assert_eq 1 "$(get_security_update_count)" || return 1
}

test_update_count_apt_none_is_zero_and_success() {
    updates_case apt
    stub apt-get 'printf "Reading package lists...\n0 upgraded, 0 newly installed\n"'
    local n
    n="$(get_update_count)" || fail "zero updates must not be an error"
    assert_eq 0 "$n" || return 1
    n="$(get_security_update_count)" || fail "zero security updates must not be an error"
    assert_eq 0 "$n" || return 1
}

test_update_count_apt_failure_is_unknown() {
    updates_case apt
    stub apt-get 'return 100'
    get_update_count >/dev/null && fail "apt failure must return non-zero"
    return 0
}

test_update_count_dnf_exit_100_means_updates_available() {
    updates_case dnf
    stub dnf 'printf "\nkernel.x86_64 6.1 baseos\nopenssl.x86_64 3.0 baseos\n"; return 100'
    assert_eq 2 "$(get_update_count)" || return 1
}

test_update_count_dnf_exit_0_means_none() {
    updates_case dnf
    stub dnf 'return 0'
    assert_eq 0 "$(get_update_count)" || return 1
}

test_update_count_dnf_other_exit_is_unknown() {
    updates_case dnf
    stub dnf 'return 1'
    get_update_count >/dev/null && fail "dnf exit 1 is an error, not 'no updates'"
    return 0
}

test_update_count_pacman_exit_1_means_none() {
    updates_case pacman
    stub pacman 'return 1'
    assert_eq 0 "$(get_update_count)" || return 1
}

test_update_count_apk() {
    updates_case apk
    stub apk 'printf "Installed:                                Available:\nbusybox-1.36-r0 < 1.36-r1\nmusl-1.2-r0 < 1.2-r1\n"'
    assert_eq 2 "$(get_update_count)" || return 1
}

test_system_updates_verdicts() {
    updates_case apt
    record_checks
    stub apt-get 'printf "Reading package lists...\n"'
    check_system_updates
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1

    stub apt-get 'printf "Inst a [1] (2 Ubuntu:24.04/noble-updates)\n"'
    check_system_updates
    assert_eq WARN "$RESULT_STATUS" || return 1

    stub apt-get 'printf "Inst a [1] (2 Ubuntu:24.04/noble-security)\n"'
    check_system_updates
    assert_eq FAIL "$RESULT_STATUS" || return 1
    assert_eq true "$RESULT_CRIT" "pending security updates are critical" || return 1

    stub apt-get 'return 100'
    check_system_updates
    assert_eq WARN "$RESULT_STATUS" "unknown must not be reported as PASS" || return 1
    assert_contains "$RESULT_MSG" "Unable" || return 1
}

# --- sshd configuration resolution -------------------------------------------

test_ssh_config_uses_effective_sshd_dump() {
    hide_system_commands
    stub sshd 'printf "port 2222\npermitrootlogin no\nallowusers alice bob\nmaxauthtries 3\n"'
    SSHD_EFFECTIVE_LOADED=false
    assert_eq 2222 "$(get_ssh_config Port 22)" || return 1
    assert_eq no "$(get_ssh_config PermitRootLogin yes)" "lookups are case-insensitive" || return 1
    assert_eq "alice bob" "$(get_ssh_config AllowUsers '')" "multi-word values are preserved" || return 1
}

test_ssh_config_returns_default_for_unset_key() {
    hide_system_commands
    stub sshd 'printf "port 22\n"'
    SSHD_EFFECTIVE_LOADED=false
    assert_eq my-default "$(get_ssh_config SettingNobodySets my-default)" || return 1
}

test_ssh_config_falls_back_to_default_without_sshd() {
    hide_system_commands
    SSHD_EFFECTIVE_LOADED=false
    # No sshd on PATH and (in a hidden-PATH test) no /etc/ssh/sshd_config
    # setting this key: the supplied default must come back verbatim.
    assert_eq my-default "$(get_ssh_config ThisSettingDoesNotExist12345 my-default)" || return 1
}

# --- /proc readers (no dependency on the `uptime` command) ----------------------
# Found by the distro matrix: minimal Rocky/Alma/openSUSE images have no
# `uptime`, and the script printed "uptime: command not found" twice.

test_get_uptime_formats_from_proc() {
    local d
    d="$(make_tmp)" || return 1
    PROC_UPTIME="$d/uptime"
    echo "273305.12 1234.5" >"$PROC_UPTIME"
    assert_eq "up 3 days, 3 hours, 55 minutes" "$(get_uptime)" || return 1
    echo "60.0 1.0" >"$PROC_UPTIME"
    assert_eq "up 1 minute" "$(get_uptime)" || return 1
    echo "3600.9 1.0" >"$PROC_UPTIME"
    assert_eq "up 1 hour" "$(get_uptime)" || return 1
    echo "5.3 1.0" >"$PROC_UPTIME"
    assert_eq "up 0 minutes" "$(get_uptime)" || return 1
}

test_get_uptime_unreadable_is_unknown() {
    PROC_UPTIME=/nonexistent/uptime
    local out rc=0
    out="$(get_uptime)" || rc=$?
    assert_eq unknown "$out" || return 1
    assert_ne 0 "$rc" || return 1
}

test_get_load_average_from_proc() {
    local d
    d="$(make_tmp)" || return 1
    PROC_LOADAVG="$d/loadavg"
    echo "0.41 0.68 0.56 1/123 4567" >"$PROC_LOADAVG"
    assert_eq "0.41, 0.68, 0.56" "$(get_load_average)" || return 1
    assert_eq "0.41" "$(get_load_average 1min)" || return 1
}

test_audit_never_calls_the_uptime_command() {
    hide_system_commands
    # With no `uptime` on PATH the helpers must still work.
    command -v uptime >/dev/null && return 1
    assert_match "$(get_uptime)" '^up ' || return 1
    assert_match "$(get_load_average)" '^[0-9.]+, [0-9.]+, [0-9.]+$' || return 1
}

# --- --no-network keeps package managers off the network ------------------------

test_no_network_makes_dnf_use_cache_only() {
    updates_case dnf
    CONFIG[skip_network]=true
    stub dnf 'echo "$*" >"$DNF_ARGS"; return 0'
    DNF_ARGS="$(make_tmp)/args"
    get_update_count >/dev/null
    assert_contains "$(cat "$DNF_ARGS")" "-C" "dnf must be told to use its cache" || return 1
}

test_no_network_makes_zypper_skip_refresh() {
    updates_case zypper
    CONFIG[skip_network]=true
    stub zypper 'echo "$*" >"$ZYPPER_ARGS"; return 0'
    ZYPPER_ARGS="$(make_tmp)/args"
    get_update_count >/dev/null
    assert_contains "$(cat "$ZYPPER_ARGS")" "--no-refresh" || return 1
}

test_network_allowed_by_default_does_not_force_cache_only() {
    updates_case dnf
    stub dnf 'echo "$*" >"$DNF_ARGS"; return 0'
    DNF_ARGS="$(make_tmp)/args"
    get_update_count >/dev/null
    assert_not_contains "$(cat "$DNF_ARGS")" "-C" || return 1
}
