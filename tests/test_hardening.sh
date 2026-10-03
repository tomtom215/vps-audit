#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034
#
# Password policy, lockout, mounts, umask, core dumps, key permissions.

pam_case() { # common-password line(s) [pwquality.conf content]
    local d
    d="$(make_tmp)" || return 1
    mkdir -p "$d/pam.d" "$d/pwq.d"
    printf '%s\n' "$1" >"$d/pam.d/common-password"
    PAM_DIR="$d/pam.d"
    PWQUALITY_CONF="$d/pwquality.conf"
    PWQUALITY_CONF_D="$d/pwq.d"
    : >"$PWQUALITY_CONF"
    [[ -n "${2:-}" ]] && printf '%s\n' "$2" >"$PWQUALITY_CONF"
    hide_system_commands
    record_checks
}

password_path() { # yes|no
    if [[ "$1" == yes ]]; then stub ssh_password_login_possible 'return 0'; else stub ssh_password_login_possible 'return 1'; fi
}

# Regression: Ubuntu with pam_pwquality active in common-password and an
# all-comments pwquality.conf reported "FAIL - No password quality policy
# detected". The old check also demanded four character classes, which NIST
# SP 800-63B says not to impose.
test_password_policy_active_module_with_long_minlen_passes() {
    pam_case "password requisite pam_pwquality.so retry=3" "minlen = 14" || return 1
    password_path yes
    check_password_policy
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_password_policy_inline_pam_minlen_counts() {
    pam_case "password requisite pam_pwquality.so retry=3 minlen=12" || return 1
    password_path yes
    check_password_policy
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_password_policy_short_minlen_warns() {
    pam_case "password requisite pam_pwquality.so retry=3" "minlen = 8" || return 1
    password_path yes
    check_password_policy
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_REC" "minlen = 12" || return 1
}

test_password_policy_does_not_require_character_classes() {
    pam_case "password requisite pam_pwquality.so" $'minlen = 16\ndcredit = 0\nucredit = 0' || return 1
    password_path yes
    check_password_policy
    assert_eq PASS "$RESULT_STATUS" "long passphrases without composition rules are fine: $RESULT_MSG" || return 1
}

test_password_policy_no_module_warns_when_passwords_are_accepted() {
    pam_case "password required pam_unix.so sha512" || return 1
    password_path yes
    check_password_policy
    assert_eq WARN "$RESULT_STATUS" || return 1
}

test_password_policy_commented_module_does_not_count() {
    pam_case "# password requisite pam_pwquality.so retry=3" || return 1
    password_path yes
    check_password_policy
    assert_eq WARN "$RESULT_STATUS" || return 1
}

test_password_policy_is_info_when_ssh_is_key_only() {
    pam_case "password required pam_unix.so" || return 1
    password_path no
    check_password_policy
    assert_eq INFO "$RESULT_STATUS" || return 1
}

# --- account lockout -----------------------------------------------------------------

test_lockout_faillock_configured_passes() {
    pam_case "auth required pam_faillock.so preauth" || return 1
    password_path yes
    stub service_is_active 'return 1'
    check_account_lockout
    assert_eq PASS "$RESULT_STATUS" || return 1
}

test_lockout_absent_warns_only_when_passwords_are_accepted() {
    pam_case "auth required pam_unix.so" || return 1
    stub service_is_active 'return 1'
    password_path yes
    check_account_lockout
    assert_eq WARN "$RESULT_STATUS" || return 1
    password_path no
    check_account_lockout
    assert_eq INFO "$RESULT_STATUS" || return 1
}

# --- temporary filesystems ---------------------------------------------------------------
# systemd mounts /dev/shm nosuid,nodev (not noexec) and /tmp is usually not a
# separate mount, so requiring noexec everywhere warned on every stock server.

tmp_case() { # /proc/mounts content
    local d
    d="$(make_tmp)" || return 1
    printf '%s\n' "$1" >"$d/mounts"
    PROC_MOUNTS="$d/mounts"
    record_checks
    check_tmp_mount_options
}

test_tmp_mounts_stock_systemd_server_is_info_not_warn() {
    tmp_case $'/dev/vda1 / ext4 rw 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0' || return 1
    assert_eq INFO "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_tmp_mounts_missing_nosuid_on_a_mounted_tmp_warns() {
    tmp_case $'/dev/vda1 / ext4 rw 0 0\ntmpfs /tmp tmpfs rw,nodev 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0' || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "/tmp" || return 1
    assert_contains "$RESULT_MSG" "nosuid" || return 1
}

test_tmp_mounts_fully_hardened_passes() {
    tmp_case $'/dev/vda1 / ext4 rw 0 0\ntmpfs /tmp tmpfs rw,nosuid,nodev,noexec 0 0\ntmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0\n/dev/vdb /var/tmp ext4 rw,nosuid,nodev,noexec 0 0' || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# --- umask ---------------------------------------------------------------------------------

umask_case() { # login.defs content
    local d
    d="$(make_tmp)" || return 1
    printf '%s\n' "$1" >"$d/login.defs"
    LOGIN_DEFS="$d/login.defs"
    PROFILE_FILES=("$d/profile")
    : >"$d/profile"
    record_checks
    check_umask_settings
}

test_umask_027_passes_and_077_passes() {
    umask_case "UMASK 027" || return 1
    assert_eq PASS "$RESULT_STATUS" || return 1
    umask_case "UMASK 077" || return 1
    assert_eq PASS "$RESULT_STATUS" || return 1
    umask_case "UMASK 037" || return 1
    assert_eq PASS "$RESULT_STATUS" "037 also denies other access: $RESULT_MSG" || return 1
}

# Ubuntu ships UMASK 022 with HOME_MODE 0750: new home directories are private.
test_umask_022_with_private_home_mode_is_fine() {
    umask_case $'UMASK 022\nHOME_MODE 0750' || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_umask_022_alone_is_info() {
    umask_case "UMASK 022" || return 1
    assert_eq INFO "$RESULT_STATUS" || return 1
}

test_umask_in_a_comment_does_not_count() {
    umask_case "UMASK 022" || return 1
    printf '# umask 027\n' >"${PROFILE_FILES[0]}"
    check_umask_settings
    assert_eq INFO "$RESULT_STATUS" "a commented-out umask must not count: $RESULT_MSG" || return 1
}

# --- core dumps ------------------------------------------------------------------------------

core_case() { # coredump.conf.d content|"" limits.d content|""
    local d
    d="$(make_tmp)" || return 1
    mkdir -p "$d/coredump.conf.d" "$d/limits.d"
    COREDUMP_CONF="$d/coredump.conf"
    COREDUMP_CONF_D="$d/coredump.conf.d"
    LIMITS_CONF="$d/limits.conf"
    LIMITS_D="$d/limits.d"
    : >"$LIMITS_CONF"
    [[ -n "$1" ]] && printf '%s\n' "$1" >"$d/coredump.conf.d/10-nodump.conf"
    [[ -n "$2" ]] && printf '%s\n' "$2" >"$d/limits.d/10-nocore.conf"
    hide_system_commands
    stub sysctl 'echo 0'
    record_checks
    check_core_dumps
}

test_core_dumps_coredump_conf_drop_in_counts() {
    core_case $'[Coredump]\nStorage=none' "" || return 1
    assert_eq PASS "$RESULT_STATUS" "Storage=none in a drop-in: $RESULT_MSG" || return 1
}

test_core_dumps_limits_drop_in_counts() {
    core_case "" "* hard core 0" || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_core_dumps_unrestricted_warns() {
    core_case "" "" || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
}

# --- sensitive file modes ---------------------------------------------------------------------

test_sensitive_permissions_accepts_0400_host_keys() {
    local d
    d="$(make_tmp)" || return 1
    printf 'k' >"$d/ssh_host_ed25519_key"
    chmod 400 "$d/ssh_host_ed25519_key"
    SSH_DIR="$d"
    detect_tool_versions
    record_checks
    check_sensitive_permissions
    assert_eq PASS "$RESULT_STATUS" "mode 400 is the strictest valid host-key mode: $RESULT_MSG" || return 1
}

test_sensitive_permissions_flags_world_readable_host_key() {
    local d
    d="$(make_tmp)" || return 1
    printf 'k' >"$d/ssh_host_ed25519_key"
    chmod 644 "$d/ssh_host_ed25519_key"
    SSH_DIR="$d"
    detect_tool_versions
    record_checks
    check_sensitive_permissions
    assert_eq FAIL "$RESULT_STATUS" || return 1
}
