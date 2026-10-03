#!/usr/bin/env bash
# shellcheck shell=bash
#
# What the user reads: priorities, assessment wording, wrapping, colour and
# encoding behaviour, report/JSON structure.

# --- priority ----------------------------------------------------------------
# Regression: priority used to be derived by substring-matching the check name
# *and* recommendation text, so a key-only root login WARN landed under
# "CRITICAL (Fix Immediately)" while a failing, critical-flagged security
# update landed under HIGH. Priority now follows the verdict itself.

test_priority_critical_fail_is_p1() {
    assert_eq 1 "$(compute_priority FAIL true "System Updates")" || return 1
}

test_priority_plain_fail_is_p2() {
    assert_eq 2 "$(compute_priority FAIL false "Intrusion Prevention")" || return 1
}

test_priority_warn_is_p3() {
    assert_eq 3 "$(compute_priority WARN false "SSH Root Login")" "key-only root login is not critical" || return 1
}

test_priority_informational_warn_is_p4() {
    assert_eq 4 "$(compute_priority WARN false "Login Banner")" || return 1
}

test_priority_info_is_p4() {
    assert_eq 4 "$(compute_priority INFO false "Anything")" || return 1
}

test_priority_ignores_recommendation_text() {
    # A name that merely *contains* a high-priority word must not be promoted.
    assert_eq 3 "$(compute_priority WARN false "Compiler Access for Docker")" || return 1
}

test_recommendations_are_ordered_by_priority() {
    CONFIG[output_format]=text
    REPORT_FILE="$(make_tmp)/report.txt"
    : >"$REPORT_FILE"
    check_security "Login Banner" WARN "none" "add a banner"
    check_security "SSH Root Login" WARN "key only" "disable root"
    check_security "System Updates" FAIL "5 security updates" "update now" true
    local out
    out="$(print_recommendations 2>&1)"
    local p1 p3 p4
    p1="${out%%System Updates*}"
    p3="${out%%SSH Root Login*}"
    p4="${out%%Login Banner*}"
    [[ ${#p1} -lt ${#p3} && ${#p3} -lt ${#p4} ]] ||
        fail "order must be System Updates, SSH Root Login, Login Banner; got: $out"
}

# --- assessment --------------------------------------------------------------
# Regression: "Poor - Critical security issues found" was printed from the
# percentage alone, even when no check was flagged critical.

test_assessment_never_claims_critical_without_critical_failures() {
    local a
    a="$(get_assessment 20 0)"
    assert_not_contains "$a" "Critical" "score 20 with 0 critical failures" || return 1
    assert_not_contains "$a" "critical" || return 1
}

test_assessment_reports_critical_failures_regardless_of_score() {
    assert_contains "$(get_assessment 95 1)" "ritical" || return 1
}

# An open FAIL must never read as "Excellent" or "Good".
test_assessment_never_praises_while_a_fail_is_open() {
    local a
    a="$(get_assessment 95 0 1)"
    assert_not_contains "$a" "Excellent" || return 1
    assert_not_contains "$a" "Good" || return 1
    assert_contains "$a" "FAILED" || return 1
}

test_assessment_bands() {
    assert_contains "$(get_assessment 95 0 0)" "Excellent" || return 1
    assert_contains "$(get_assessment 75 0)" "Good" || return 1
    assert_contains "$(get_assessment 55 0)" "Fair" || return 1
    assert_contains "$(get_assessment 10 0)" "Poor" || return 1
}

# --- wrapping ----------------------------------------------------------------
# Observed at 80 columns: long lines hard-wrapped mid-word with no indent
# ("Ava/ilable", "dum/ps"). wrap_text breaks at word boundaries and indents
# continuation lines under the message.

test_wrap_text_breaks_on_words_and_indents() {
    local out
    out="$(wrap_text 20 4 "the quick brown fox jumps over the lazy dog")"
    local expected=$'the quick brown fox\n    jumps over the\n    lazy dog'
    assert_eq "$expected" "$out" || return 1
}

test_wrap_text_never_exceeds_width() {
    local out line
    out="$(wrap_text 30 7 "$(printf 'word%d ' {1..40})")"
    while IFS= read -r line; do
        [[ ${#line} -le 30 ]] || fail "line longer than 30: [$line]"
    done <<<"$out"
}

test_wrap_text_splits_overlong_words() {
    local out line
    out="$(wrap_text 10 2 "/very/long/path/with/no/spaces/at/all")"
    while IFS= read -r line; do
        [[ ${#line} -le 10 ]] || fail "line longer than 10: [$line]"
    done <<<"$out"
    assert_contains "$(printf '%s' "$out" | tr -d '\n ')" "/very/long/path/with/no/spaces/at/all" "no characters lost" || return 1
}

test_wrap_text_zero_width_means_no_wrapping() {
    local s="a b c d e f g h i j k l m n o p q r s t u v w x y z"
    assert_eq "$s" "$(wrap_text 0 7 "$s")" || return 1
}

test_wrap_text_does_not_glob_expand() {
    local d out
    d="$(make_tmp)" || return 1
    touch "$d/should-not-appear"
    cd "$d" || return 1
    out="$(wrap_text 80 2 "export * (rw) here")"
    assert_eq "export * (rw) here" "$out" "an asterisk in the text must stay an asterisk" || return 1
    rm -rf "$d"
}

# --- colour / encoding -------------------------------------------------------

test_no_color_env_disables_colour_when_set_to_any_value() {
    stdout_is_tty() { return 0; }
    NO_COLOR=0 init_colors
    assert_eq "" "$GREEN" "NO_COLOR=0 must disable colour (no-color.org: any non-empty value)" || return 1
}

test_term_dumb_disables_colour() {
    stdout_is_tty() { return 0; }
    TERM=dumb init_colors
    assert_eq "" "$GREEN" || return 1
}

test_colour_enabled_on_a_tty_by_default() {
    stdout_is_tty() { return 0; }
    unset NO_COLOR
    TERM=xterm-256color init_colors
    assert_ne "" "$GREEN" || return 1
}

test_script_source_is_pure_ascii() {
    # Terminal output must not depend on the viewer's charset (PuTTY defaults,
    # serial consoles, LC_ALL=C). The script forces LC_ALL=C for parsing, so
    # it must also only ever emit ASCII.
    # [^ -~[:space:]] matches any byte outside printable ASCII + whitespace;
    # unlike `grep -P` it works with BusyBox grep too, and a grep *error* must
    # not read as "no hits".
    local hits rc=0
    hits="$(LC_ALL=C grep -n '[^ -~[:space:]]' "$AUDIT_SCRIPT" | head -5)" || rc=$?
    [[ $rc -le 1 ]] || fail "grep failed (exit $rc)" || return 1
    assert_eq "" "$hits" "non-ASCII bytes in vps-audit.sh" || return 1
}

test_guide_output_is_ascii_and_fits_80_columns() {
    run_audit --guide
    assert_status 0 "$STATUS" || return 1
    local bad rc=0
    bad="$(printf '%s\n' "$OUT" | LC_ALL=C grep -n '[^ -~[:space:]]' | head -3)" || rc=$?
    [[ $rc -le 1 ]] || fail "grep failed (exit $rc)" || return 1
    assert_eq "" "$bad" "non-ASCII bytes in --guide output" || return 1
    local longest
    longest="$(printf '%s\n' "$OUT" | awk '{ if (length($0) > m) m = length($0) } END { print m + 0 }')"
    [[ $longest -le 80 ]] || fail "guide has a line of $longest columns"
}

# --- INFO status --------------------------------------------------------------

test_info_is_shown_but_never_scored() {
    local d
    d="$(make_tmp)" || return 1
    REPORT_FILE="$d/report.txt"
    : >"$REPORT_FILE"
    CONFIG[output_format]=text
    init_colors
    check_security "Check A" PASS "fine" ""
    check_security "Check B" INFO "worth knowing" "optional tweak"
    assert_eq "1 0 0 1" "$PASS_COUNT $WARN_COUNT $FAIL_COUNT $INFO_COUNT" || return 1
    assert_contains "$(cat "$REPORT_FILE")" "[INFO] Check B - worth knowing" || return 1
    # The optional tweak is listed, as low priority.
    assert_eq "4|[Check B] optional tweak" "${RECOMMENDATIONS[0]}" || return 1
}

test_info_cannot_be_critical() {
    local d
    d="$(make_tmp)" || return 1
    REPORT_FILE="$d/report.txt"
    : >"$REPORT_FILE"
    init_colors
    check_security "Check" INFO "fyi" "" true
    assert_eq 0 "$CRITICAL_FAIL_COUNT" || return 1
}

test_invalid_status_is_rejected() {
    local d
    d="$(make_tmp)" || return 1
    REPORT_FILE="$d/report.txt"
    : >"$REPORT_FILE"
    init_colors
    check_security "Check" MAYBE "msg" "" 2>/dev/null && return 1
    assert_eq 0 "$((PASS_COUNT + WARN_COUNT + FAIL_COUNT + INFO_COUNT))" || return 1
}
