#!/usr/bin/env bash
# shellcheck shell=bash
#
# Command-line behaviour as a user sees it. These run the script as a
# subprocess; none of them need root (help/version/guide/dry-run exit before
# the root check).

# --- help / version / guide --------------------------------------------------

test_cli_help_exits_zero_and_documents_usage() {
    run_audit --help
    assert_status 0 "$STATUS" || return 1
    assert_contains "$OUT" "Usage:" || return 1
    assert_contains "$OUT" "--checks" || return 1
    assert_contains "$OUT" "Exit Codes" || return 1
}

test_cli_help_works_with_other_flags() {
    run_audit -q -o /nonexistent/dir --help
    assert_status 0 "$STATUS" || return 1
    assert_contains "$OUT" "Usage:" || return 1
}

test_cli_version_matches_VERSION_constant() {
    run_audit --version
    assert_status 0 "$STATUS" || return 1
    assert_eq "VPS Security Audit Tool v$VERSION" "$OUT" || return 1
    assert_match "$VERSION" '^[0-9]+\.[0-9]+\.[0-9]+$' "VERSION must be semver" || return 1
}

test_cli_guide_exits_zero_without_root() {
    run_audit --guide
    assert_status 0 "$STATUS" || return 1
    assert_contains "$OUT" "Quick-Start Hardening Guide" || return 1
}

# --- argument errors ---------------------------------------------------------

test_cli_unknown_option_exits_one() {
    run_audit --no-such-flag
    assert_status 1 "$STATUS" || return 1
    assert_contains "$OUT" "Unknown option: --no-such-flag" || return 1
}

test_cli_option_missing_value_exits_one() {
    local flag
    for flag in -o -f --checks --disk-warn; do
        run_audit "$flag"
        assert_status 1 "$STATUS" "$flag with no value" || return 1
        assert_contains "$OUT" "requires" "$flag with no value" || return 1
    done
}

test_cli_invalid_format_exits_one() {
    run_audit -f xml
    assert_status 1 "$STATUS" || return 1
    assert_contains "$OUT" "Invalid format" || return 1
}

test_cli_non_numeric_threshold_exits_one() {
    run_audit --disk-warn lots
    assert_status 1 "$STATUS" || return 1
}

test_cli_threshold_warn_must_be_below_fail() {
    run_audit --disk-warn 80 --disk-fail 50
    assert_status 1 "$STATUS" || return 1
    assert_contains "$OUT" "Threshold error" || return 1
}

# Regression: validate_percentage existed but parse_args never called it, so
# "--disk-warn 150 --disk-fail 200" was accepted and made the check meaningless.
test_cli_percentage_thresholds_are_bounded() {
    run_audit --disk-warn 150 --disk-fail 200
    assert_status 1 "$STATUS" || return 1
    assert_contains "$OUT" "1-100" || return 1
    run_audit --mem-warn 0 --mem-fail 50
    assert_status 1 "$STATUS" "0% is not a usable threshold" || return 1
}

# --- --checks validation -----------------------------------------------------
# Regression: an unknown category (typo, or a category renamed in a new
# release) silently matched nothing, so a cron job ran an empty audit and
# reported "No security recommendations - your system passed all checks!".

test_cli_unknown_check_category_is_rejected() {
    run_audit --dry-run --checks ssh,firewal
    assert_status 1 "$STATUS" || return 1
    assert_contains "$OUT" "Unknown check category: firewal" || return 1
    assert_contains "$OUT" "firewall" "error should list valid categories" || return 1
}

test_cli_checks_list_is_trimmed_and_case_sensitive_keys() {
    run_audit --dry-run --checks "ssh, firewall"
    assert_status 0 "$STATUS" "spaces after commas are tolerated" || return 1
    run_audit --dry-run --checks SSH
    assert_status 1 "$STATUS" "keys are lowercase" || return 1
}

# --- dry run / category single source of truth -------------------------------

test_cli_dry_run_lists_every_category() {
    run_audit --dry-run
    assert_status 0 "$STATUS" || return 1
    local key
    for key in $(category_keys); do
        assert_contains "$OUT" "$key" "dry-run must list category '$key'" || return 1
    done
}

test_cli_dry_run_marks_unselected_checks_skipped() {
    run_audit --dry-run --checks ssh
    assert_status 0 "$STATUS" || return 1
    assert_contains "$OUT" "[x]" || return 1
    assert_contains "$OUT" "(skipped)" || return 1
}

test_cli_help_documents_every_category() {
    run_audit --help
    local key
    for key in $(category_keys); do
        printf '%s\n' "$OUT" | grep -qE "^    $key +" || fail "--help must document category '$key'"
    done
}

# Every category a check function asks for must be a declared one, and every
# declared category must be used by at least one check.
test_cli_every_should_run_check_category_is_declared() {
    local used declared key
    used="$(grep -oE 'should_run_check "[a-z]+"' "$AUDIT_SCRIPT" | sed 's/.*"\(.*\)"/\1/' | sort -u)"
    declared="$(category_keys | sort -u)"
    for key in $used; do
        [[ $'\n'"$declared"$'\n' == *$'\n'"$key"$'\n'* ]] || fail "should_run_check \"$key\" is not in CHECK_CATEGORIES"
    done
    for key in $declared; do
        [[ $'\n'"$used"$'\n' == *$'\n'"$key"$'\n'* ]] || fail "category '$key' is declared but no check uses it"
    done
}

test_readme_category_table_matches_script() {
    local readme="$REPO_DIR/README.md" key
    for key in $(category_keys); do
        grep -qE "^\| \`?$key\`? +\|" "$readme" || fail "README category table is missing '$key'"
    done
    # and nothing extra
    local rows
    rows="$(sed -n '/^| Category | Description |/,/^$/p' "$readme" | grep -cE '^\| `?[a-z]+`? +\|')"
    assert_eq "$(category_keys | wc -l | tr -d ' ')" "$rows" "README lists a different number of categories than the script" || return 1
}

# --- non-interactive output --------------------------------------------------

test_cli_output_has_no_escape_sequences_when_not_a_tty() {
    run_audit --dry-run
    assert_not_contains "$OUT" $'\033' "no ANSI escapes when stdout is not a terminal" || return 1
    run_audit --guide
    assert_not_contains "$OUT" $'\033' || return 1
}

# --- configuration file ------------------------------------------------------

test_config_file_sets_defaults_and_cli_overrides_it() {
    local d
    d="$(make_tmp)" || return 1
    printf 'THRESHOLDS[disk_warn]=61\nTHRESHOLDS[disk_fail]=91\n' >"$d/.vps-audit.conf"
    chmod 600 "$d/.vps-audit.conf"
    HOME="$d" load_config
    assert_eq 61 "${THRESHOLDS[disk_warn]}" "config file value" || return 1
    parse_args --disk-warn 70
    assert_eq 70 "${THRESHOLDS[disk_warn]}" "CLI beats config" || return 1
    assert_eq 91 "${THRESHOLDS[disk_fail]}" "untouched config value survives" || return 1
    rm -rf "$d"
}

test_config_file_writable_by_group_is_ignored() {
    local d
    d="$(make_tmp)" || return 1
    printf 'THRESHOLDS[disk_warn]=61\nTHRESHOLDS[disk_fail]=91\n' >"$d/.vps-audit.conf"
    chmod 664 "$d/.vps-audit.conf"
    local before="${THRESHOLDS[disk_warn]}"
    HOME="$d" load_config 2>/dev/null
    assert_eq "$before" "${THRESHOLDS[disk_warn]}" "a group-writable config is never sourced as root" || return 1
    rm -rf "$d"
}

test_config_file_not_owned_by_root_or_caller_is_ignored() {
    [[ "$(id -u)" == 0 ]] || return 77 # needs root to create a foreign-owned file
    local d
    d="$(make_tmp)" || return 1
    printf 'THRESHOLDS[disk_warn]=61\nTHRESHOLDS[disk_fail]=91\n' >"$d/.vps-audit.conf"
    chmod 600 "$d/.vps-audit.conf"
    chown 12345 "$d/.vps-audit.conf"
    local before="${THRESHOLDS[disk_warn]}"
    HOME="$d" load_config 2>/dev/null
    assert_eq "$before" "${THRESHOLDS[disk_warn]}" || return 1
    rm -rf "$d"
}
