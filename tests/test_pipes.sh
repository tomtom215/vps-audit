#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2016,SC2034,SC2154
#
# vps-audit.sh runs under `set -o pipefail`. A pipeline whose last stage stops
# reading early (`grep -q`, `head -1`) makes a producer that is still writing die
# of SIGPIPE, and pipefail then reports the whole pipeline as failed even though
# the pattern matched. It only happens when the producer writes more than a pipe
# buffer, i.e. on busy or Docker hosts, so it looks like a flaky verdict.
#
# Every producer below prints the line that matters FIRST and then enough filler
# to overflow the pipe, which is the worst case for each check.

big_output() {
    local i
    for ((i = 0; i < ${1:-30000}; i++)); do
        printf 'filler line %d with some padding to take up space\n' "$i"
    done
}

test_the_hazard_is_real_in_this_shell() {
    # Guard for the tests below: if this fails they prove nothing. The pipeline
    # fails although grep matched, whether the writer dies of SIGPIPE (status
    # 141) or, with SIGPIPE ignored as under systemd and on GitHub's runners,
    # gets "Broken pipe" and exits 1.
    local rc
    (
        set -o pipefail
        big_output 2>/dev/null | grep -q 'filler line 0 '
    )
    rc=$?
    assert_ne 0 "$rc" "grep -q before a large producer must fail under pipefail (default SIGPIPE)" || return 1
    (
        trap '' PIPE
        set -o pipefail
        big_output 2>/dev/null | grep -q 'filler line 0 '
    )
    rc=$?
    assert_ne 0 "$rc" "the same with SIGPIPE ignored" || return 1
}

test_iptables_default_deny_survives_a_large_ruleset() {
    hide_system_commands
    stub iptables 'echo "-P INPUT DROP"; big_output 30000'
    local i
    for i in 1 2 3; do
        iptables_input_default_deny iptables || fail "run $i: policy DROP on the first line was missed" || return 1
    done
}

# systemd services and GitHub's runners start processes with SIGPIPE ignored.
test_iptables_default_deny_survives_a_large_ruleset_with_sigpipe_ignored() {
    hide_system_commands
    trap '' PIPE
    stub iptables 'echo "-P INPUT DROP"; big_output 30000'
    iptables_input_default_deny iptables || fail "policy DROP on the first line was missed" || return 1
}

test_iptables_final_drop_survives_a_large_ruleset() {
    hide_system_commands
    stub iptables 'echo "-P INPUT ACCEPT"; big_output 30000 | sed "s/^/-A INPUT -s 10.0.0.1 -m comment --comment /"; echo "-A INPUT -j DROP"'
    iptables_input_default_deny iptables || fail "unconditional final DROP was missed" || return 1
}

test_loaded_dangerous_protocol_is_seen_with_a_long_module_list() {
    hide_system_commands
    stub lsmod 'echo "dccp                  20480  0"; big_output 20000'
    MODPROBE_DIR="$(make_tmp)" || return 1
    record_checks
    check_dangerous_protocols
    assert_eq WARN "$RESULT_STATUS" "$RESULT_MSG" || return 1
    assert_contains "$RESULT_MSG" "dccp" || return 1
}

test_loaded_usb_storage_is_seen_with_a_long_module_list() {
    hide_system_commands
    local d
    d="$(make_tmp)" || return 1
    mkdir -p "$d/usb" "$d/modprobe.d"
    USB_BUS_DIR="$d/usb"
    MODPROBE_DIR="$d/modprobe.d"
    echo "blacklist usb-storage" >"$MODPROBE_DIR/usb.conf"
    stub lsmod 'echo "usb_storage           77824  0"; big_output 20000'
    record_checks
    check_usb_storage
    assert_ne PASS "$RESULT_STATUS" "blacklisted but still loaded must not read as disabled: $RESULT_MSG" || return 1
}

test_process_accounting_data_is_seen_with_a_long_history() {
    hide_system_commands
    OS_INFO[pkg_manager]=apt
    OS_INFO[service_manager]=none
    stub dpkg 'return 1'
    stub lastcomm 'big_output 30000'
    record_checks
    check_process_accounting
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_rootless_docker_is_seen_in_a_long_docker_info() {
    hide_system_commands
    stub docker 'case "$1" in
        info) echo "Security Options: rootless"; big_output 20000 ;;
        ps) return 0 ;;
        *) return 0 ;;
    esac'
    record_checks
    docker_daemon_security
    assert_contains "$RESULT_MSG" "rootless" || return 1
}

# Forward guard: a pipe into `grep -q` is the shape that breaks. Read the
# producer into a variable and use a here-string, or let grep read everything
# (`grep pattern >/dev/null`). A `tail` in front is fine, because tail reads
# its whole input. Values captured with $(... | head) are also fine: only the
# captured text is used, never the pipeline's status.
test_no_pipe_into_grep_q_in_the_script() {
    local hits
    hits="$(grep -nE '[^|]\|[[:space:]]*grep[[:space:]]+-[a-zA-Z]*q' "$AUDIT_SCRIPT" | grep -v 'tail -n 1 |' || true)"
    assert_eq "" "$hits" "pipe into grep -q (pipefail turns this into a false negative)" || return 1
}
