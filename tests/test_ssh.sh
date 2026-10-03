#!/usr/bin/env bash
# shellcheck shell=bash
#
# SSH checks, driven by a stubbed `sshd -T` effective-configuration dump
# (lowercase keys, as OpenSSH prints them).

# ssh_case "key value" ... : replace the sshd dump with these lines. A later line
# overrides an earlier one with the same key, because a real `sshd -T` prints each
# key once.
ssh_case() {
    hide_system_commands
    local -A merged=()
    local -a order=()
    local line key
    for line in "$@"; do
        key="${line%% *}"
        [[ -n "${merged[$key]+x}" ]] || order+=("$key")
        merged["$key"]="$line"
    done
    SSHD_DUMP=""
    for key in "${order[@]}"; do
        SSHD_DUMP+="${merged[$key]}"$'\n'
    done
    stub sshd 'printf "%s\n" "$SSHD_DUMP"'
    SSHD_EFFECTIVE_LOADED=false
    record_checks
}

# --- password login paths ----------------------------------------------------
# Verified against a live sshd (OpenSSH 9.6): with PasswordAuthentication no,
# KbdInteractiveAuthentication yes and UsePAM yes a password login SUCCEEDED
# while the check reported "Password authentication disabled, key-based only".

test_ssh_password_auth_off_and_kbd_off_passes() {
    ssh_case "passwordauthentication no" "kbdinteractiveauthentication no" "usepam yes" || return 1
    check_ssh_password_auth
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_ssh_password_auth_yes_warns() {
    ssh_case "passwordauthentication yes" "kbdinteractiveauthentication no" "usepam yes" || return 1
    check_ssh_password_auth
    assert_eq WARN "$RESULT_STATUS" || return 1
}

test_ssh_keyboard_interactive_with_pam_is_a_password_path() {
    ssh_case "passwordauthentication no" "kbdinteractiveauthentication yes" "usepam yes" || return 1
    check_ssh_password_auth
    assert_eq WARN "$RESULT_STATUS" "$RESULT_MSG" || return 1
    assert_contains "$RESULT_REC" "KbdInteractiveAuthentication no" || return 1
}

# Alpine's sshd has no PAM, so keyboard-interactive has nothing to ask.
test_ssh_keyboard_interactive_without_pam_is_not_a_password_path() {
    ssh_case "passwordauthentication no" "kbdinteractiveauthentication yes" || return 1
    check_ssh_password_auth
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_ssh_authentication_methods_publickey_only_blocks_password_paths() {
    ssh_case "passwordauthentication yes" "kbdinteractiveauthentication yes" "usepam yes" \
        "authenticationmethods publickey" || return 1
    check_ssh_password_auth
    assert_eq PASS "$RESULT_STATUS" "AuthenticationMethods publickey: $RESULT_MSG" || return 1
}

# "publickey,password" needs the key AND a password: a password alone is useless.
test_ssh_authentication_methods_key_plus_password_is_not_password_only() {
    ssh_case "passwordauthentication yes" "authenticationmethods publickey,password" || return 1
    check_ssh_password_auth
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_ssh_authentication_methods_with_a_password_only_alternative_warns() {
    ssh_case "passwordauthentication yes" "authenticationmethods publickey password" || return 1
    check_ssh_password_auth
    assert_eq WARN "$RESULT_STATUS" "a space separates ALTERNATIVES: $RESULT_MSG" || return 1
}

# --- SSH hardening -------------------------------------------------------------
# The old check scored 7 settings, three of them "free points" for defaults
# (Ciphers, PermitEmptyPasswords, PubkeyAuthentication), so a stock sshd_config
# scored 3/7 and printed "FAIL - SSH poorly hardened".

STOCK_SSHD=(
    "permitemptypasswords no" "pubkeyauthentication yes" "maxauthtries 6"
    "x11forwarding yes" "clientaliveinterval 0" "clientalivecountmax 3"
    "ciphers chacha20-poly1305@openssh.com,aes128-ctr,aes256-gcm@openssh.com"
)

test_ssh_hardening_stock_config_is_not_a_failure() {
    ssh_case "${STOCK_SSHD[@]}" || return 1
    check_ssh_hardening_extended
    find_result "SSH Hardening" || return 1
    assert_eq PASS "$RESULT_STATUS" "stock config: $RESULT_MSG" || return 1
}

test_ssh_hardening_hints_go_to_info_not_the_score() {
    ssh_case "${STOCK_SSHD[@]}" || return 1
    local statuses=""
    check_security() { statuses+="$1=$2;"; }
    check_ssh_hardening_extended
    assert_contains "$statuses" "SSH Hardening=PASS" || return 1
    assert_contains "$statuses" "SSH Optional Hardening=INFO" "X11/idle-timeout/AllowUsers are optional" || return 1
}

test_ssh_hardening_empty_passwords_allowed_fails() {
    ssh_case "${STOCK_SSHD[@]}" "permitemptypasswords yes" || return 1
    check_ssh_hardening_extended
    find_result "SSH Hardening" || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "PermitEmptyPasswords" || return 1
}

test_ssh_hardening_weak_cipher_warns() {
    ssh_case "${STOCK_SSHD[@]}" "ciphers aes128-cbc,aes256-ctr" || return 1
    check_ssh_hardening_extended
    find_result "SSH Hardening" || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "aes128-cbc" || return 1
}

test_ssh_hardening_pubkey_disabled_warns() {
    ssh_case "${STOCK_SSHD[@]}" "pubkeyauthentication no" || return 1
    check_ssh_hardening_extended
    find_result "SSH Hardening" || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
}

test_ssh_hardening_max_auth_tries_above_default_warns() {
    ssh_case "${STOCK_SSHD[@]}" "maxauthtries 10" || return 1
    check_ssh_hardening_extended
    find_result "SSH Hardening" || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_REC" "MaxAuthTries 4" "state the wanted value" || return 1
}
