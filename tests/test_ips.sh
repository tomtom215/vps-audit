#!/usr/bin/env bash
# shellcheck shell=bash
#
# Intrusion prevention. "fail2ban is running" is not protection when it has no
# jails (AlmaLinux + EPEL ships every jail disabled), and the CrowdSec engine
# alone only detects: remediation needs a bouncer.

ips_case() { # fail2ban-state(none|inactive|jails:N) crowdsec-state(none|engine|bouncer) password-path(yes|no)
    OS_INFO[pkg_manager]=apt
    OS_INFO[service_manager]=systemd
    hide_system_commands
    IPS_F2B="$1" IPS_CS="$2"
    # dpkg -l PKG: the package name is the last argument
    stub dpkg 'pkg="${@: -1}"; case "$pkg" in
        fail2ban) [[ "$IPS_F2B" != none ]] && printf "ii  fail2ban\n" ;;
        crowdsec) [[ "$IPS_CS" != none ]] && printf "ii  crowdsec\n" ;;
        crowdsec-firewall-bouncer*) [[ "$IPS_CS" == bouncer ]] && printf "ii  crowdsec-firewall-bouncer\n" ;;
    esac'
    stub systemctl '[[ "$1" == "is-active" ]] || return 1
        case "$2" in
            fail2ban) [[ "$IPS_F2B" == jails:* ]] ;;
            crowdsec) [[ "$IPS_CS" != none ]] ;;
            crowdsec-firewall-bouncer) [[ "$IPS_CS" == bouncer ]] ;;
            *) return 1 ;;
        esac'
    stub fail2ban-client 'printf "Status\n|- Number of jail:\t%s\n" "${IPS_F2B#jails:}"'
    if [[ "$3" == yes ]]; then
        stub ssh_password_login_possible 'return 0'
    else
        stub ssh_password_login_possible 'return 1'
    fi
    record_checks
    check_intrusion_prevention
}

test_ips_fail2ban_with_jails_passes() {
    ips_case jails:2 none no || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_ips_fail2ban_running_without_jails_warns() {
    ips_case jails:0 none no || return 1
    assert_eq WARN "$RESULT_STATUS" "$RESULT_MSG" || return 1
    assert_contains "$RESULT_MSG" "no jails" || return 1
}

test_ips_crowdsec_engine_without_bouncer_warns() {
    ips_case none engine no || return 1
    assert_eq WARN "$RESULT_STATUS" "$RESULT_MSG" || return 1
    assert_contains "$RESULT_MSG" "bouncer" || return 1
}

test_ips_crowdsec_with_bouncer_passes() {
    ips_case none bouncer no || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_ips_absent_is_warn_when_password_logins_are_possible() {
    ips_case none none yes || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
}

# With key-only SSH there is little for fail2ban to do; it must not cost score.
test_ips_absent_is_info_when_ssh_is_key_only() {
    ips_case none none no || return 1
    assert_eq INFO "$RESULT_STATUS" || return 1
}

test_ips_installed_but_stopped_warns() {
    ips_case inactive none no || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
}
