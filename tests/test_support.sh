#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2016,SC2034,SC2154
#
# End-of-support detection. SUPPORT_END from /etc/os-release is used when the
# distribution provides it (Fedora, RHEL family, Amazon Linux); Ubuntu and
# Debian do not, so a small embedded table (EOL_TABLE) covers them.

today_is() { # YYYY-MM-DD
    TODAY_FAKE="$1"
    stub today_iso 'echo "$TODAY_FAKE"'
}

support_case() { # id version today [os-release content]
    OS_INFO[id]="$1" OS_INFO[version]="$2" OS_INFO[name]="${1^} $2"
    today_is "$3"
    local d
    d="$(make_tmp)" || return 1
    printf '%s\n' "${4:-}" >"$d/os-release"
    OS_RELEASE_FILE="$d/os-release"
    record_checks
    check_os_support
}

test_date_to_days_matches_gnu_date() {
    assert_eq 0 "$(date_to_days 1970-01-01)" || return 1
    assert_eq 20729 "$(date_to_days 2026-10-03)" || return 1
    assert_eq 19782 "$(date_to_days 2024-02-29)" "leap day" || return 1
    assert_eq 11017 "$(date_to_days 2000-03-01)" "century leap year" || return 1
}

test_support_ubuntu_current_lts_passes() {
    support_case ubuntu 24.04 2026-10-03 || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
    assert_contains "$RESULT_MSG" "2029-05-31" || return 1
}

test_support_ubuntu_past_standard_support_warns_about_esm() {
    support_case ubuntu 20.04 2026-10-03 || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "2025-05-31" || return 1
    assert_contains "$RESULT_MSG" "ESM" || return 1
    assert_contains "$RESULT_MSG" "2030-04-23" || return 1
}

test_support_ubuntu_past_all_support_is_critical() {
    support_case ubuntu 16.04 2026-10-03 || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
    assert_eq true "$RESULT_CRIT" || return 1
    assert_contains "$RESULT_MSG" "no longer receives security updates" || return 1
}

test_support_ubuntu_interim_release_ends_with_its_standard_date() {
    support_case ubuntu 25.10 2026-10-03 || return 1
    assert_eq FAIL "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_support_debian_lts_phase_warns() {
    support_case debian 12 2026-10-03 || return 1
    assert_eq WARN "$RESULT_STATUS" || return 1
    assert_contains "$RESULT_MSG" "LTS" || return 1
    assert_contains "$RESULT_MSG" "2028-06-30" || return 1
}

test_support_debian_after_lts_is_critical() {
    support_case debian 11 2026-10-03 || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
    assert_eq true "$RESULT_CRIT" || return 1
}

test_support_current_debian_passes() {
    support_case debian 13 2026-10-03 || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
}

test_support_ending_within_90_days_warns() {
    support_case ubuntu 22.04 2027-04-01 || return 1
    assert_eq WARN "$RESULT_STATUS" "61 days before 2027-06-01: $RESULT_MSG" || return 1
    assert_contains "$RESULT_MSG" "2027-06-01" || return 1
}

test_support_end_from_os_release_is_used() {
    support_case fedora 44 2026-10-03 'SUPPORT_END=2027-05-19' || return 1
    assert_eq PASS "$RESULT_STATUS" "$RESULT_MSG" || return 1
    support_case fedora 43 2026-12-30 'SUPPORT_END=2026-12-02' || return 1
    assert_eq FAIL "$RESULT_STATUS" || return 1
}

test_support_end_value_may_be_quoted() {
    support_case rocky 9 2026-10-03 'SUPPORT_END="2032-05-31"' || return 1
    assert_eq PASS "$RESULT_STATUS" "Rocky quotes the value: $RESULT_MSG" || return 1
}

test_support_unknown_distribution_is_info() {
    support_case alpine 3.24 2026-10-03 || return 1
    assert_eq INFO "$RESULT_STATUS" || return 1
    assert_not_contains "$RESULT_MSG" "supported until" || return 1
}

test_eol_table_is_well_formed() {
    local entry key std ext n=0
    for entry in "${EOL_TABLE[@]}"; do
        IFS='|' read -r key std ext <<<"$entry"
        [[ "$key" =~ ^(ubuntu|debian):[0-9]+(\.[0-9]+)?$ ]] || fail "bad key in [$entry]" || return 1
        [[ "$std" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ && "$ext" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fail "bad date in [$entry]" || return 1
        [[ "$std" < "$ext" || "$std" == "$ext" ]] || fail "standard end after extended end in [$entry]" || return 1
        n=$((n + 1))
    done
    [[ $n -ge 20 ]] || fail "table has only $n entries"
}
