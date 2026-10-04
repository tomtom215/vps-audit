#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2016
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
        grep -qE "^    $key +" <<<"$OUT" || fail "--help must document category '$key'"
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
    rows="$(sed -n '/^| Category | Covers |/,/^$/p' "$readme" | grep -cE '^\| `?[a-z]+`? +\|')"
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

# --- structural lint ----------------------------------------------------------------

# Found when a stale second definition of check_sgid_files silently overrode the
# rewritten one: in Bash the later definition wins, and nothing warns.
test_script_defines_every_function_once() {
    local dups
    dups="$(grep -oE '^[a-zA-Z_][a-zA-Z0-9_]*\(\) \{' "$AUDIT_SCRIPT" | sort | uniq -d)"
    assert_eq "" "$dups" "functions defined more than once" || return 1
}

# Every check function must be called from main(), or it is dead code that
# looks like coverage.
test_every_check_function_is_called_from_main() {
    # The body of main() is read once into a variable and matched with a
    # here-string: `awk | grep -q` under pipefail fails whenever grep exits
    # before awk has finished writing (it did, on 12 of 20 distro images).
    local fn missing="" body
    body="$(awk '/^main\(\) \{/ {m=1} m' "$AUDIT_SCRIPT")"
    for fn in $(grep -oE '^check_[a-z0-9_]+\(\)' "$AUDIT_SCRIPT" | tr -d '()' | grep -vx check_security); do
        grep -qE "^[[:space:]]+${fn}\$" <<<"$body" || missing+="$fn "
    done
    assert_eq "" "$missing" "check functions never called by main()" || return 1
}

# This project is not contributing to, or targeting, the repository it was
# derived from; nothing should link to it. (LICENSE keeps the original
# copyright notice, which the MIT license requires, and names no URL.)
test_no_links_to_the_original_repository() {
    local hits
    hits="$(grep -rIn --exclude-dir=.git --exclude-dir=test-results 'github.com/vern[u]' "$TESTS_DIR/.." || true)"
    assert_eq "" "$hits" "links to the original repository" || return 1
}

# The help text is read in a terminal. Invoked as ./vps-audit.sh (how the
# README shows it) no line may be wider than a classic 80-column terminal.
test_help_fits_80_columns() {
    local longest
    longest="$(cd "$REPO_DIR" && ./vps-audit.sh --help | awk '{ if (length($0) > m) m = length($0) } END { print m + 0 }')"
    [[ $longest -le 80 ]] || fail "--help has a line of $longest columns" || return 1
}

# The README says which systems the matrix covers; it must list every image
# tests/matrix.sh runs, and nothing else.
test_readme_lists_every_matrix_image_and_nothing_else() {
    local readme="$REPO_DIR/README.md" image listed
    local -a images=()
    while read -r image _; do
        images+=("$image")
        grep -qF "\`$image\`" "$readme" || fail "README does not list the matrix image $image" || return 1
    done < <("$REPO_DIR/tests/matrix.sh" -l)
    [[ ${#images[@]} -gt 0 ]] || fail "matrix.sh -l printed nothing" || return 1
    # Every container image named in the Tested systems tables is in the matrix.
    while read -r listed; do
        [[ " ${images[*]} " == *" $listed "* ]] || fail "README names $listed, which is not in the matrix" || return 1
    done < <(sed -n '/^### Tested systems/,/^## Usage/p' "$readme" | grep -oE '^\| [^|]+\| `[^`]+`' | grep -oE '`[^`]+`' | tr -d '`')
}

# A README image that does not exist shows as a broken icon on the project page.
test_readme_images_exist() {
    local readme="$REPO_DIR/README.md" path n=0
    while read -r path; do
        n=$((n + 1))
        [[ -f "$REPO_DIR/$path" ]] || fail "README links $path, which does not exist" || return 1
    done < <(grep -oE '\]\(docs/[^)]+\)' "$readme" | sed -E 's/^\]\(//; s/\)$//')
    [[ $n -gt 0 ]] || fail "README links no images under docs/" || return 1
}
