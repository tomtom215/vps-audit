#!/usr/bin/env bash
# shellcheck shell=bash
#
# Severity calibration. A check that reports WARN on every correctly run VPS
# (Secure Boot on a cloud VM, no USB bus, no compiler policy, ...) drags the
# score and trains people to ignore the report. These reach INFO instead: shown,
# never scored. The verdict for a *real* problem stays WARN/FAIL.

# --- login banner -------------------------------------------------------------

banner_case() { # /etc/issue content
    local d
    d="$(make_tmp)" || return 1
    printf '%s' "$1" >"$d/issue"
    ISSUE_FILE="$d/issue"
    hide_system_commands
    stub sshd 'printf "banner none\n"'
    SSHD_EFFECTIVE_LOADED=false
    record_checks
    check_login_banner
}

# Regression: the default-issue test `\\\\n|\\\\l` could not match a literal \n,
# so the stock /etc/issue of Alma, Rocky, Fedora, Alpine, Arch and Amazon Linux
# counted as a custom warning banner.
test_banner_stock_issue_files_are_not_a_banner() {
    local content
    for content in \
        $'\\S\nKernel \\r on an \\m\n' \
        $'Ubuntu 24.04.5 LTS \\n \\l\n' \
        $'Debian GNU/Linux 13 \\n \\l\n' \
        $'Welcome to Alpine Linux 3.23\nKernel \\r on an \\m (\\l)\n' \
        $'Arch Linux \\r (\\l)\n'; do
        banner_case "$content" || return 1
        assert_eq INFO "$RESULT_STATUS" "stock issue [$content]: $RESULT_MSG" || return 1
    done
}

test_banner_real_warning_text_passes() {
    banner_case $'Authorized use only. All activity may be monitored and reported.\nDisconnect now if you are not an authorized user.\n' || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_banner_ssh_banner_must_exist_and_have_text() {
    local d
    d="$(make_tmp)" || return 1
    : >"$d/empty"
    printf 'Authorized access only.\n' >"$d/real"
    ISSUE_FILE=/nonexistent
    hide_system_commands
    stub sshd 'printf "banner %s\n" "$SSH_BANNER_PATH"'
    SSH_BANNER_PATH="$d/empty"
    SSHD_EFFECTIVE_LOADED=false
    record_checks
    check_login_banner
    assert_eq INFO "$RESULT_STATUS" "an empty banner file is not a banner" || return 1
    SSH_BANNER_PATH="$d/real"
    SSHD_EFFECTIVE_LOADED=false
    check_login_banner
    assert_eq PASS "$RESULT_STATUS" || return 1
}

# --- cron access control -----------------------------------------------------------
# Regression: AlmaLinux ships an EMPTY /etc/cron.deny and no cron.allow, which
# restricts nobody, yet counted as "access control present".

cron_case() { # allow-content|ABSENT deny-content|ABSENT
    local d
    d="$(make_tmp)" || return 1
    CRON_ALLOW="$d/cron.allow"
    CRON_DENY="$d/cron.deny"
    [[ "$1" == ABSENT ]] || printf '%s' "$1" >"$CRON_ALLOW"
    [[ "$2" == ABSENT ]] || printf '%s' "$2" >"$CRON_DENY"
    hide_system_commands
    detect_tool_versions
    stub crontab 'return 0'
    record_checks
    check_cron_security
}

test_cron_empty_deny_file_is_not_access_control() {
    cron_case ABSENT "" || return 1
    assert_ne PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_cron_allow_file_is_access_control() {
    cron_case $'root\n' ABSENT || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_cron_deny_file_with_entries_is_access_control() {
    cron_case ABSENT $'baduser\n' || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_cron_not_installed_is_info() {
    CRON_ALLOW=/nonexistent/allow CRON_DENY=/nonexistent/deny
    CRON_SPOOL_DIRS=(/nonexistent/a)
    hide_system_commands
    detect_tool_versions
    record_checks
    check_cron_security
    assert_eq INFO "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# --- time synchronisation --------------------------------------------------------------

test_time_sync_ntpsynchronized_yes_passes() {
    hide_system_commands
    stub timedatectl 'case "$*" in *NTPSynchronized*) echo yes ;; *NTP*) echo yes ;; esac'
    OS_INFO[service_manager]=none
    record_checks
    check_time_sync
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# The NTP service being enabled does not mean the clock is synchronised.
test_time_sync_service_enabled_but_not_synchronised_warns() {
    hide_system_commands
    stub timedatectl 'case "$*" in *NTPSynchronized*) echo no ;; *NTP*) echo yes ;; esac'
    OS_INFO[service_manager]=none
    record_checks
    check_time_sync
    assert_eq WARN "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_time_sync_recognises_ntpsec_and_openntpd() {
    local svc
    for svc in ntpsec openntpd; do
        hide_system_commands
        TS_SVC="$svc"
        stub service_is_active '[[ "$1" == "$TS_SVC" ]]'
        record_checks
        check_time_sync
        assert_eq PASS "$RESULT_STATUS" "$svc: $RESULT_MSG" || return 1
    done
}

# --- the rest of the optional checks ----------------------------------------------------

test_compiler_presence_is_info() {
    hide_system_commands
    stub gcc 'return 0'
    record_checks
    check_compiler_access
    assert_eq INFO "$RESULT_STATUS" || return 1
}

test_compiler_absent_passes() {
    hide_system_commands
    record_checks
    check_compiler_access
    assert_eq PASS "$RESULT_STATUS" || return 1
}

test_process_accounting_absent_is_info() {
    hide_system_commands
    OS_INFO[pkg_manager]=apt
    stub dpkg 'return 1'
    record_checks
    check_process_accounting
    assert_eq INFO "$RESULT_STATUS" || return 1
}

test_usb_storage_on_a_machine_without_usb_passes() {
    local d
    d="$(make_tmp)" || return 1
    USB_BUS_DIR="$d/no-usb"
    hide_system_commands
    record_checks
    check_usb_storage
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_usb_storage_not_restricted_on_hardware_is_info() {
    local d
    d="$(make_tmp)" || return 1
    mkdir "$d/usb"
    USB_BUS_DIR="$d/usb"
    MODPROBE_DIR="$d/modprobe.d"
    mkdir "$MODPROBE_DIR"
    hide_system_commands
    stub lsmod 'return 0'
    record_checks
    check_usb_storage
    assert_eq INFO "$RESULT_STATUS" || return 1
}

test_secure_boot_disabled_is_info() {
    local d
    d="$(make_tmp)" || return 1
    mkdir -p "$d/efi/efivars"
    EFI_DIR="$d/efi"
    printf '\x07\x00\x00\x00\x00' >"$d/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    hide_system_commands
    record_checks
    check_secure_boot
    assert_eq INFO "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_audit_daemon_missing_is_info_but_stopped_is_warn() {
    hide_system_commands
    OS_INFO[pkg_manager]=apt
    stub dpkg 'return 1'
    record_checks
    check_audit_system
    assert_eq INFO "$RESULT_STATUS" || return 1
    stub dpkg 'printf "ii  auditd\n"'
    OS_INFO[service_manager]=systemd
    stub systemctl 'return 1'
    record_checks
    check_audit_system
    assert_eq WARN "$RESULT_STATUS" || return 1
}

test_file_integrity_tool_installed_passes_and_absent_is_info() {
    hide_system_commands
    record_checks
    check_file_integrity_monitoring
    assert_eq INFO "$RESULT_STATUS" || return 1
    stub aide 'return 0'
    check_file_integrity_monitoring
    assert_eq PASS "$RESULT_STATUS" || return 1
}

test_rootkit_scanner_absent_is_info() {
    hide_system_commands
    record_checks
    check_rootkit_detection
    assert_eq INFO "$RESULT_STATUS" || return 1
}

test_running_services_count_is_informational() {
    get_running_services_count() { echo 37; }
    record_checks
    check_running_services
    assert_eq INFO "$RESULT_STATUS" "a service count has no pass/fail threshold" || return 1
    assert_contains "$RESULT_MSG" "37" || return 1
}

test_cpu_sample_is_informational() {
    record_checks
    check_cpu_usage
    assert_eq INFO "$RESULT_STATUS" "a 1-second sample must not fail an audit" || return 1
}

# --- resource thresholds --------------------------------------------------------------------

test_resource_threshold_defaults_are_80_and_90() {
    assert_eq "80 90 80 90" "${THRESHOLDS[disk_warn]} ${THRESHOLDS[disk_fail]} ${THRESHOLDS[mem_warn]} ${THRESHOLDS[mem_fail]}" || return 1
}

test_help_states_the_resource_defaults() {
    run_audit --help
    assert_contains "$OUT" "Disk usage warning threshold (default: 80)" || return 1
    assert_contains "$OUT" "Memory usage failure threshold (default: 90)" || return 1
}

# --- sudo -----------------------------------------------------------------------------------

sudo_case() { # sudoers-content [sudoers.d file content...]
    local d
    d="$(make_tmp)" || return 1
    mkdir "$d/sudoers.d"
    printf '%s' "$1" >"$d/sudoers"
    chmod 440 "$d/sudoers"
    SUDOERS_FILE="$d/sudoers"
    SUDOERS_DIR="$d/sudoers.d"
    SUDOERS_RS="$d/sudoers-rs"
    if [[ -n "${2:-}" ]]; then
        printf '%s' "$2" >"$d/sudoers.d/90-cloud-init-users"
    fi
    detect_tool_versions
    record_checks
    check_sudoers_security
}

test_sudoers_clean_passes() {
    sudo_case $'root ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n' || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# NOPASSWD is the cloud-init default and is reasonable with key-only SSH.
# Advising "remove it" without "set a password first" locks the user out of sudo.
test_sudoers_nopasswd_is_info_and_warns_about_lockout() {
    sudo_case $'root ALL=(ALL:ALL) ALL\n' $'ubuntu ALL=(ALL) NOPASSWD:ALL\n' || return 1
    assert_eq INFO "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_REC" "password" "must say to set a password first" || return 1
}

test_sudoers_safe_modes_are_not_flagged() {
    local mode
    for mode in 400 440 600 640; do
        sudo_case $'root ALL=(ALL:ALL) ALL\n' || return 1
        chmod "$mode" "$SUDOERS_FILE"
        check_sudoers_security
        assert_eq PASS "$RESULT_STATUS" "mode $mode: $RESULT_MSG" || return 1
    done
}

test_sudoers_unsafe_modes_are_flagged() {
    local mode
    for mode in 666 664 644 660 444; do
        sudo_case $'root ALL=(ALL:ALL) ALL\n' || return 1
        chmod "$mode" "$SUDOERS_FILE"
        check_sudoers_security
        assert_eq WARN "$RESULT_STATUS" "mode $mode must be flagged" || return 1
    done
}

test_sudoers_world_writable_file_is_warn() {
    sudo_case $'root ALL=(ALL:ALL) ALL\n' || return 1
    chmod 666 "$SUDOERS_FILE"
    check_sudoers_security
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "permissions" || return 1
}

# sudo-rs (Ubuntu 25.10+) reads /etc/sudoers-rs INSTEAD of /etc/sudoers when it exists.
test_sudoers_rs_file_is_scanned_when_present() {
    sudo_case $'root ALL=(ALL:ALL) ALL\n' || return 1
    printf 'evil ALL=(ALL) NOPASSWD: ALL\n' >"$SUDOERS_RS"
    chmod 440 "$SUDOERS_RS"
    check_sudoers_security
    assert_eq INFO "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "sudoers-rs" || return 1
}

test_sudo_logging_passes_by_default_and_warns_only_when_disabled() {
    local d
    d="$(make_tmp)" || return 1
    mkdir "$d/sudoers.d"
    printf 'root ALL=(ALL) ALL\n' >"$d/sudoers"
    SUDOERS_FILE="$d/sudoers"
    SUDOERS_DIR="$d/sudoers.d"
    OS_INFO[service_manager]=sysv
    record_checks
    check_sudo_logging
    assert_eq PASS "$RESULT_STATUS" "sudo logs to syslog unless told not to: $RESULT_MSG" || return 1
    printf 'Defaults !syslog\n' >>"$d/sudoers"
    check_sudo_logging
    assert_eq WARN "$RESULT_STATUS" || return 1
}
