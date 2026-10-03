#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2016,SC2034
#
# Pending reboots, Docker-published ports, IPv6 exposure, effective sysctl values.

# --- pending kernel reboot -----------------------------------------------------------
# Debian has no /var/run/reboot-required producer, so a kernel update there
# never raised "restart required". Comparing the running kernel with the newest
# installed one works everywhere a kernel lives in /boot.

kernel_case() { # running-release  installed-kernel...
    local d k
    d="$(make_tmp)" || return 1
    for k in "${@:2}"; do : >"$d/vmlinuz-$k"; done
    BOOT_DIR="$d"
    REBOOT_REQUIRED_FILE="$d/none"
    hide_system_commands
    KERNEL_RUNNING="$1"
    stub uname '[[ "$1" == "-r" ]] && echo "$KERNEL_RUNNING"'
    record_checks
    check_system_restart
}

test_reboot_newer_installed_kernel_warns() {
    kernel_case 6.8.0-45-generic 6.8.0-45-generic 6.8.0-47-generic || return 1
    assert_eq WARN "$RESULT_STATUS" "$RESULT_MSG" || return 1
    assert_contains "$RESULT_MSG" "6.8.0-47-generic" || return 1
}

test_reboot_running_the_newest_kernel_passes() {
    kernel_case 6.8.0-47-generic 6.8.0-45-generic 6.8.0-47-generic || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_reboot_version_compare_is_numeric_not_lexical() {
    kernel_case 6.8.0-9-generic 6.8.0-9-generic 6.8.0-10-generic || return 1
    assert_eq WARN "$RESULT_STATUS" "10 is newer than 9: $RESULT_MSG" || return 1
}

test_reboot_other_flavours_and_rescue_images_are_ignored() {
    kernel_case 6.1.0-25-amd64 6.1.0-25-amd64 0-rescue-3fa9c1d2 6.9.0-1-rt-arm64 || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_reboot_rhel_style_kernel_names() {
    kernel_case 5.14.0-427.13.1.el9_4.x86_64 5.14.0-427.13.1.el9_4.x86_64 5.14.0-503.11.1.el9_5.x86_64 || return 1
    assert_eq WARN "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_reboot_provider_kernel_with_nothing_in_boot_passes() {
    kernel_case 6.8.0-45-generic || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_reboot_required_file_still_counts() {
    kernel_case 6.8.0-45-generic 6.8.0-45-generic || return 1
    : >"$REBOOT_REQUIRED_FILE"
    check_system_restart
    assert_eq WARN "$RESULT_STATUS" || return 1
}

# --- Docker published ports ------------------------------------------------------------
# Docker publishes ports through its own iptables rules, ahead of ufw/firewalld,
# so `ufw deny 8081` does not stop a container published on 0.0.0.0:8081.

docker_case() { # ps-lines  firewall(active|none)
    hide_system_commands
    DOCKER_PS="$1"
    stub docker 'case "$1" in
        info) return 0 ;;
        ps) if [[ "$*" == *"Names"* ]]; then printf "%s\n" "$DOCKER_PS"; fi ;;
    esac'
    if [[ "$2" == active ]]; then stub ufw_is_protecting 'return 0'; else stub ufw_is_protecting 'return 1'; fi
    stub firewalld_is_running 'return 1'
    record_checks
    check_docker_security
}

test_docker_published_port_bypassing_the_firewall_warns() {
    docker_case 'web|0.0.0.0:18081->8081/tcp, [::]:18081->8081/tcp' active || return 1
    find_result "Docker Published Ports" || return 1
    assert_eq WARN "$RESULT_STATUS" "$RESULT_MSG" || return 1
    assert_contains "$RESULT_MSG" "web:18081" || return 1
    assert_contains "$RESULT_MSG" "ufw" || return 1
    assert_contains "$RESULT_REC" "127.0.0.1" || return 1
}

test_docker_published_http_and_https_are_expected() {
    docker_case $'proxy|0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp, [::]:443->443/tcp' active || return 1
    find_result "Docker Published Ports" || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_docker_loopback_published_ports_are_fine() {
    docker_case 'db|127.0.0.1:5432->5432/tcp' active || return 1
    find_result "Docker Published Ports" || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_docker_published_port_without_a_host_firewall_is_info() {
    docker_case 'web|0.0.0.0:18081->8081/tcp' none || return 1
    find_result "Docker Published Ports" || return 1
    assert_eq INFO "$RESULT_STATUS" "there is no host firewall to bypass: $RESULT_MSG" || return 1
}

test_docker_unpublished_container_ports_are_ignored() {
    docker_case 'worker|5432/tcp, 6379/tcp' active || return 1
    find_result "Docker Published Ports" || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# --- IPv6 ---------------------------------------------------------------------------------

ipv6_case() { # if_inet6-content  disable_ipv6-value  [nft-fixture|-]  [ufw yes|no|-]
    local d
    d="$(make_tmp)" || return 1
    printf '%s' "$1" >"$d/if_inet6"
    printf '%s\n' "$2" >"$d/disable_ipv6"
    PROC_IF_INET6="$d/if_inet6"
    PROC_IPV6_DISABLE="$d/disable_ipv6"
    UFW_DEFAULTS="$d/ufw-default"
    hide_system_commands
    if [[ "${3:--}" != "-" ]]; then
        NFT_FX="$TESTS_DIR/fixtures/firewall/$3"
        stub nft 'cat "$NFT_FX"'
    fi
    stub ufw_is_protecting 'return 1'
    stub firewalld_is_running 'return 1'
    case "${4:--}" in
        yes)
            stub ufw_is_protecting 'return 0'
            printf 'IPV6=yes\n' >"$UFW_DEFAULTS"
            ;;
        no)
            stub ufw_is_protecting 'return 0'
            printf 'IPV6=no\n' >"$UFW_DEFAULTS"
            ;;
    esac
    record_checks
    check_ipv6_security
}

GLOBAL_V6=$'20010db8000000000000000000000005 02 40 00 80 eth0\n'
LINKLOCAL_V6=$'fe800000000000000000000000000001 02 40 20 80 eth0\n'

test_ipv6_disabled_passes() {
    ipv6_case "" 1 || return 1
    assert_eq PASS "$RESULT_STATUS" || return 1
}

test_ipv6_without_a_global_address_passes() {
    ipv6_case "$LINKLOCAL_V6" 0 || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

# Regression: `ip6tables -L INPUT | wc -l` counted rules, so a native nftables
# default-deny policy (no ip6tables rules at all) read as "no firewall", and a
# host with no ip6tables binary passed unconditionally.
test_ipv6_reachable_with_nft_default_deny_passes() {
    ipv6_case "$GLOBAL_V6" 0 nft-policy-drop.txt || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_ipv6_reachable_with_only_an_ipv4_firewall_warns() {
    ipv6_case "$GLOBAL_V6" 0 nft-iptables-policy-drop.txt || return 1
    assert_eq WARN "$RESULT_STATUS" "an ip-family ruleset does not filter IPv6: $RESULT_MSG" || return 1
    assert_contains "$RESULT_REC" "IPV6=yes" || return 1
}

test_ipv6_reachable_with_no_firewall_warns() {
    ipv6_case "$GLOBAL_V6" 0 || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
}

test_ipv6_ufw_with_ipv6_enabled_passes() {
    ipv6_case "$GLOBAL_V6" 0 - yes || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_ipv6_ufw_with_ipv6_disabled_in_ufw_warns() {
    ipv6_case "$GLOBAL_V6" 0 - no || return 1
    assert_eq WARN "$RESULT_STATUS" "UFW is active but IPV6=no in /etc/default/ufw: $RESULT_MSG" || return 1
}

# --- effective sysctl values --------------------------------------------------------------------

test_rp_filter_uses_the_effective_value_not_just_all() {
    # RHEL's 50-redhat.conf leaves "all" at 0 and sets each interface to 1: the
    # kernel applies max(all, interface), so the effective value is 1.
    local d
    d="$(make_tmp)" || return 1
    mkdir -p "$d/eth0" "$d/lo" "$d/all" "$d/default"
    echo 1 >"$d/eth0/rp_filter"
    echo 0 >"$d/lo/rp_filter"
    echo 0 >"$d/all/rp_filter"
    echo 1 >"$d/default/rp_filter"
    IPV4_CONF_DIR="$d"
    sysctl_values "${KERNEL_OK[@]}" net.ipv4.conf.all.rp_filter=0
    record_checks
    check_kernel_hardening
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_rp_filter_flags_an_interface_with_no_validation() {
    local d
    d="$(make_tmp)" || return 1
    mkdir -p "$d/eth0" "$d/all" "$d/default"
    echo 0 >"$d/eth0/rp_filter"
    echo 0 >"$d/all/rp_filter"
    echo 1 >"$d/default/rp_filter"
    IPV4_CONF_DIR="$d"
    sysctl_values "${KERNEL_OK[@]}" net.ipv4.conf.all.rp_filter=0
    record_checks
    check_kernel_hardening
    assert_ne PASS "$RESULT_STATUS" "eth0 has rp_filter 0 and all is 0: $RESULT_MSG" || return 1
}

test_sysrq_176_is_acceptable() {
    # Ubuntu's default: sync + remount-ro + reboot, keyboard-only; harmless on a VPS.
    sysctl_values "${NETWORK_OK[@]}" kernel.sysrq=176
    record_checks
    check_network_sysctl
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_sysrq_fully_enabled_is_flagged() {
    sysctl_values "${NETWORK_OK[@]}" kernel.sysrq=1
    record_checks
    check_network_sysctl
    assert_ne PASS "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_REC" "kernel.sysrq" || return 1
}
