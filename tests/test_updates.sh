#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2016,SC2034,SC2154
#
# Update checks. Found by review and reproduced against real configuration:
# - unattended-upgrades installed but APT::Periodic::Unattended-Upgrade "0"
#   was reported as "Automatic security updates configured";
# - dnf-automatic's default timer only DOWNLOADS (apply_updates = no) yet passed,
#   while dnf-automatic-install.timer was rejected;
# - `apt-get -s upgrade` on an empty package index reported "All packages are
#   up to date".

# auto_updates_apt <lists-value> <upgrade-value> [installed=true]
auto_updates_apt() {
    OS_INFO[pkg_manager]=apt
    hide_system_commands
    APT_LISTS_VAL="$1" APT_UU_VAL="$2"
    stub apt-config 'printf "APT::Periodic::Update-Package-Lists \"%s\";\nAPT::Periodic::Unattended-Upgrade \"%s\";\n" "$APT_LISTS_VAL" "$APT_UU_VAL"'
    if [[ "${3:-true}" == "true" ]]; then
        stub dpkg 'printf "ii  unattended-upgrades 2.9 all automatic installation\n"'
    else
        stub dpkg 'return 1'
    fi
    record_checks
    check_auto_updates
}

test_auto_updates_apt_enabled_passes() {
    auto_updates_apt 1 1 || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_auto_updates_apt_installed_but_disabled_warns() {
    auto_updates_apt 1 0 || return 1
    assert_eq WARN "$RESULT_STATUS" "installed-but-off must not pass" || return 1
    assert_contains "$RESULT_MSG" "disabled" || return 1
    assert_contains "$RESULT_REC" "20auto-upgrades" || return 1
}

test_auto_updates_apt_not_installed_warns() {
    auto_updates_apt 0 0 false || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_REC" "unattended-upgrades" || return 1
}

dnf_case() { # installed-timers (space separated active units) apply_updates-value
    OS_INFO[pkg_manager]=dnf
    OS_INFO[service_manager]=systemd
    hide_system_commands
    ACTIVE_UNITS="$1"
    stub systemctl '[[ "$1" == "is-active" && " $ACTIVE_UNITS " == *" $2 "* ]]'
    local d
    d="$(make_tmp)" || return 1
    printf '[commands]\napply_updates = %s\n' "$2" >"$d/automatic.conf"
    DNF_AUTOMATIC_CONF="$d/automatic.conf"
    record_checks
    check_auto_updates
}

test_auto_updates_dnf_install_timer_passes() {
    dnf_case "dnf-automatic-install.timer" no || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_auto_updates_dnf_default_timer_with_apply_no_only_downloads() {
    dnf_case "dnf-automatic.timer" no || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "does not install" || return 1
}

test_auto_updates_dnf_default_timer_with_apply_yes_passes() {
    dnf_case "dnf-automatic.timer" yes || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_auto_updates_dnf5_timer_passes() {
    dnf_case "dnf5-automatic.timer" yes || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_auto_updates_dnf_nothing_active_warns() {
    dnf_case "" no || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
}

# No reliable detection exists for these: say so instead of a permanent WARN
# that the user can never clear.
test_auto_updates_unsupported_package_manager_is_info() {
    local pm
    for pm in zypper pacman apk; do
        OS_INFO[pkg_manager]=$pm
        record_checks
        check_auto_updates
        assert_eq INFO "$RESULT_STATUS" "$pm: $RESULT_MSG" || return 1
    done
}

# --- package index freshness -------------------------------------------------------

apt_index_case() { # lists-file-count stamp-age-days upgrade-output
    OS_INFO[pkg_manager]=apt
    hide_system_commands
    local d i
    d="$(make_tmp)" || return 1
    mkdir -p "$d/lists"
    for ((i = 0; i < $1; i++)); do : >"$d/lists/archive.ubuntu.com_dists_noble_main_binary-amd64_Packages.lz4"; done
    APT_LISTS_DIR="$d/lists"
    APT_UPDATE_STAMP="$d/stamp"
    if [[ "$2" != "none" ]]; then
        : >"$APT_UPDATE_STAMP"
        touch -d "$2 days ago" "$APT_UPDATE_STAMP"
    fi
    UPGRADE_OUT="$3"
    stub apt-get 'printf "%s\n" "$UPGRADE_OUT"'
    record_checks
    check_system_updates
}

test_system_updates_empty_apt_index_is_not_up_to_date() {
    apt_index_case 0 none "Reading package lists..." || return 1
    assert_eq WARN "$RESULT_STATUS" "$RESULT_MSG" || return 1
    assert_contains "$RESULT_MSG" "package index" || return 1
    assert_contains "$RESULT_REC" "apt update" || return 1
}

test_system_updates_stale_apt_index_is_flagged_but_counts_are_reported() {
    apt_index_case 3 20 "Inst a [1] (2 Ubuntu:24.04/noble-updates)" || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "20 days old" || return 1
}

test_system_updates_fresh_index_up_to_date_passes() {
    apt_index_case 3 1 "Reading package lists..." || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# Pending security updates are a FAIL, but they are not "critical": a fresh
# image on patch day would otherwise exit 2 like a missing firewall.
test_system_updates_pending_security_is_fail_but_not_critical() {
    apt_index_case 3 1 "Inst a [1] (2 Ubuntu:24.04/noble-security)" || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
    assert_eq false "$RESULT_CRIT" || return 1
}

# An apt failure means "unknown"; it must never read as "all up to date".
test_system_updates_apt_failure_is_unknown_not_pass() {
    apt_index_case 3 1 "" || return 1
    stub apt-get 'return 100'
    record_checks
    check_system_updates
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "Unable" || return 1
}
