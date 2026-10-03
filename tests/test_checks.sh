#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034,SC2154,SC2329
#
# Verdict logic of individual checks, driven by stubbed commands and fixture
# files (PASSWD_FILE / SHADOW_FILE / PROC_MOUNTS are overridable for this).

# --- sysctl-based checks -----------------------------------------------------

test_kernel_hardening_all_good_passes() {
    sysctl_values "${KERNEL_OK[@]}"
    record_checks
    check_kernel_hardening
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# Regression: values were compared with exact equality, so a *stricter*
# setting (kptr_restrict=2, rp_filter=2) counted as a failure.
test_kernel_hardening_stricter_values_pass() {
    sysctl_values "${KERNEL_OK[@]}" kernel.kptr_restrict=2 net.ipv4.conf.all.rp_filter=2
    record_checks
    check_kernel_hardening
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# Regression: the recommendation printed the *current* insecure value
# ("rp_filter=0"), which reads as the setting to apply.
test_kernel_hardening_recommendation_states_wanted_value() {
    sysctl_values "${KERNEL_OK[@]}" net.ipv4.conf.all.rp_filter=0
    record_checks
    check_kernel_hardening
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_REC" "net.ipv4.conf.all.rp_filter = 1" "must say what to set" || return 1
    assert_not_contains "$RESULT_REC" "rp_filter=0" "must not echo the insecure value as the fix" || return 1
}

test_kernel_hardening_lists_every_failing_setting() {
    sysctl_values "${KERNEL_OK[@]}" net.ipv4.conf.all.rp_filter=0 kernel.dmesg_restrict=0
    record_checks
    check_kernel_hardening
    assert_contains "$RESULT_REC" "rp_filter" || return 1
    assert_contains "$RESULT_REC" "dmesg_restrict" "not only the first (hash-order) failure" || return 1
}

test_kernel_hardening_unavailable_parameters_are_not_failures() {
    # A kernel without the parameter cannot be told to set it; it is excluded
    # from scoring instead of counted as insecure.
    sysctl_values kernel.randomize_va_space=2 net.ipv4.tcp_syncookies=1
    record_checks
    check_kernel_hardening
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_kernel_hardening_mostly_bad_fails() {
    sysctl_values kernel.randomize_va_space=0 net.ipv4.tcp_syncookies=0 \
        net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 \
        kernel.kptr_restrict=0 kernel.dmesg_restrict=0
    record_checks
    check_kernel_hardening
    assert_eq FAIL "$RESULT_STATUS" || return 1
}

test_network_sysctl_all_good_passes() {
    sysctl_values "${NETWORK_OK[@]}"
    record_checks
    check_network_sysctl
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# Regression: the check message promised "ptrace_scope>=1" but compared with
# exact equality, failing the stricter values 2 and 3.
test_network_sysctl_ptrace_scope_at_least_one() {
    sysctl_values "${NETWORK_OK[@]}" kernel.yama.ptrace_scope=2
    record_checks
    check_network_sysctl
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_network_sysctl_recommendation_states_wanted_values() {
    sysctl_values "${NETWORK_OK[@]}" net.ipv4.conf.all.accept_redirects=1 net.ipv4.conf.all.send_redirects=1
    record_checks
    check_network_sysctl
    assert_contains "$RESULT_REC" "net.ipv4.conf.all.accept_redirects = 0" || return 1
    assert_contains "$RESULT_REC" "net.ipv4.conf.all.send_redirects = 0" || return 1
}

# Container hosts need forwarding; telling them to disable it breaks Docker.
test_network_sysctl_ip_forward_is_expected_on_container_hosts() {
    sysctl_values "${NETWORK_OK[@]}" net.ipv4.ip_forward=1
    hide_system_commands
    stub docker 'return 0'
    record_checks
    check_network_sysctl
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_network_sysctl_ip_forward_flagged_without_container_runtime() {
    sysctl_values "${NETWORK_OK[@]}" net.ipv4.ip_forward=1
    hide_system_commands
    record_checks
    check_network_sysctl
    assert_ne PASS "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_REC" "net.ipv4.ip_forward = 0" || return 1
}

# --- user accounts -----------------------------------------------------------

users_case() { # passwd_content shadow_content
    local d
    d="$(make_tmp)" || return 1
    printf '%s' "$1" >"$d/passwd"
    printf '%s' "$2" >"$d/shadow"
    PASSWD_FILE="$d/passwd"
    SHADOW_FILE="$d/shadow"
    record_checks
    check_user_accounts
}

CLEAN_PASSWD=$'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n'
CLEAN_SHADOW=$'root:$6$abc:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\nalice:$6$def:19000:0:99999:7:::\n'

test_users_clean_system_passes() {
    users_case "$CLEAN_PASSWD" "$CLEAN_SHADOW" || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# Regression: README promised empty-password detection, but the check only
# logged a count at debug level and never reported it. (It also counted "!" and
# "!!" - locked accounts - as "empty".)
test_users_empty_password_is_reported_by_name() {
    users_case "$CLEAN_PASSWD" $'root:$6$abc:19000::::::\ndaemon:*:1::::::\nalice::19000:0:99999:7:::\n' || return 1
    assert_eq FAIL "$RESULT_STATUS" "$RESULT_MSG" || return 1
    assert_contains "$RESULT_MSG" "alice" "the account must be named" || return 1
    assert_contains "$RESULT_MSG" "empty password" || return 1
}

test_users_locked_accounts_are_not_empty_passwords() {
    users_case "$CLEAN_PASSWD" $'root:$6$abc:1::::::\ndaemon:!:1::::::\nalice:!!:1::::::\n' || return 1
    assert_eq PASS "$RESULT_STATUS" "locked (!, !!) is not empty: $RESULT_MSG" || return 1
}

test_users_empty_password_on_nologin_account_is_ignored() {
    # No login shell: the empty field cannot be used to get a session.
    users_case $'root:x:0:0:root:/root:/bin/bash\nsvc:x:998:998::/var/lib/svc:/usr/sbin/nologin\n' \
        $'root:$6$a:1::::::\nsvc::1::::::\n' || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_users_second_uid0_account_is_critical() {
    users_case $'root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0:t:/root:/bin/sh\n' $'root:$6$a:1::::::\ntoor:$6$b:1::::::\n' || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
    assert_eq true "$RESULT_CRIT" || return 1
    assert_contains "$RESULT_MSG" "toor" || return 1
}

test_users_system_accounts_with_login_shell_are_named() {
    users_case $'root:x:0:0:root:/root:/bin/bash\nbackup:x:34:34::/var/backups:/bin/bash\nsync:x:4:65534::/bin:/bin/sync\n' \
        $'root:$6$a:1::::::\nbackup:*:1::::::\nsync:*:1::::::\n' || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "backup" "name the account instead of only counting" || return 1
    assert_not_contains "$RESULT_MSG" "sync" "/bin/sync is a deliberate non-login shell" || return 1
}

test_users_unreadable_shadow_does_not_fail_the_check() {
    local d
    d="$(make_tmp)" || return 1
    printf '%s' "$CLEAN_PASSWD" >"$d/passwd"
    PASSWD_FILE="$d/passwd"
    SHADOW_FILE="$d/missing"
    record_checks
    check_user_accounts
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# --- SUID / SGID ------------------------------------------------------------------
# Found by running the audit on clean images: stock installs reported
# "SUID files to review" (pam_timestamp_check, userhelper, ssh-keysign, ksu,
# sudo.ws), and an SGID verdict never named the file.

suid_case() { # files... (printed by a stubbed find_files_by_perm)
    SUID_FOUND=$(printf '%s\n' "$@")
    find_files_by_perm() { printf '%s\n' "$SUID_FOUND" | grep .; }
    local d
    d="$(make_tmp)" || return 1
    REPORT_FILE="$d/report.txt"
    : >"$REPORT_FILE"
    record_checks
}

test_suid_standard_binaries_pass() {
    suid_case /usr/bin/sudo /usr/sbin/pam_timestamp_check /usr/lib/ssh/ssh-keysign || return 1
    scan_special_files SUID "${KNOWN_SAFE_SUID[@]}"
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_suid_unexpected_file_is_named_in_the_message() {
    suid_case /usr/bin/sudo /srv/vol/planted-suid || return 1
    scan_special_files SUID "${KNOWN_SAFE_SUID[@]}"
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "/srv/vol/planted-suid" || return 1
    assert_contains "$RESULT_REC" "dpkg -S" "tell the user how to check the file" || return 1
}

# A path that merely ENDS in a safe name must not be exempt.
test_suid_lookalike_path_is_not_exempt() {
    suid_case /opt/evil/bin/su || return 1
    scan_special_files SUID "${KNOWN_SAFE_SUID[@]}"
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "/opt/evil/bin/su" || return 1
}

# Each of these was reported as "outside the standard set" on an unmodified
# image in the distro matrix (Ubuntu 22.04/24.04/26.04, Alma/Rocky 9 and 10,
# Amazon Linux 2023, Arch).
test_sgid_helpers_shipped_by_the_distributions_pass() {
    suid_case /usr/sbin/pam_extrausers_chkpwd /usr/libexec/utempter/utempter \
        /usr/libexec/openssh/ssh-keysign /usr/bin/unix_chkpwd || return 1
    scan_special_files SGID "${KNOWN_SAFE_SGID[@]}"
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_sgid_unexpected_file_is_named_too() {
    suid_case /usr/bin/wall /usr/local/bin/odd-sgid || return 1
    scan_special_files SGID "${KNOWN_SAFE_SGID[@]}"
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "/usr/local/bin/odd-sgid" || return 1
    assert_contains "$RESULT_REC" "chmod g-s" || return 1
}

test_suid_message_truncates_long_lists_but_report_has_all() {
    suid_case /x/1 /x/2 /x/3 /x/4 /x/5 || return 1
    scan_special_files SUID "${KNOWN_SAFE_SUID[@]}"
    assert_contains "$RESULT_MSG" "and 2 more" || return 1
    assert_contains "$(cat "$REPORT_FILE")" "/x/5" "the report lists every file" || return 1
}

test_suid_scan_skipped_with_no_suid_flag() {
    CONFIG[skip_suid_scan]=true
    record_checks
    check_suid_files
    check_sgid_files
    assert_eq 0 "$RESULT_COUNT" "no verdicts when the scan is skipped" || return 1
}
