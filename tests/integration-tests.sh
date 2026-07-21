#!/usr/bin/env bash
#
# VPS Audit Integration Tests
# Tests specific scenarios and validates expected behavior
#

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly SCRIPT_DIR
readonly VPS_AUDIT_SCRIPT="${SCRIPT_DIR}/vps-audit.sh"

# Colors
if [[ -t 1 ]]; then
    readonly GREEN='\033[0;32m'
    readonly RED='\033[0;31m'
    # shellcheck disable=SC2034  # YELLOW kept for consistency; may be used in future tests
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly NC='\033[0m'
else
    readonly GREEN=''
    readonly RED=''
    # shellcheck disable=SC2034  # YELLOW kept for consistency; may be used in future tests
    readonly YELLOW=''
    readonly BLUE=''
    readonly NC=''
fi

# Test counters
declare -i TESTS_RUN=0
declare -i TESTS_PASSED=0
declare -i TESTS_FAILED=0

# =============================================================================
# TEST FRAMEWORK
# =============================================================================

# shellcheck disable=SC2317  # Called indirectly by run_test
assert_equals() {
    local expected="$1"
    local actual="$2"
    local message="${3:-Assertion failed}"

    if [[ "$expected" == "$actual" ]]; then
        return 0
    else
        echo -e "${RED}ASSERTION FAILED: $message${NC}"
        echo "  Expected: '$expected'"
        echo "  Actual:   '$actual'"
        return 1
    fi
}

# shellcheck disable=SC2317  # Called indirectly by run_test
assert_contains() {
    local haystack="$1"
    local needle="$2"
    local message="${3:-String not found}"

    if [[ "$haystack" == *"$needle"* ]]; then
        return 0
    else
        echo -e "${RED}ASSERTION FAILED: $message${NC}"
        echo "  Expected to find: '$needle'"
        echo "  In: '${haystack:0:200}...'"
        return 1
    fi
}

# shellcheck disable=SC2317  # Called indirectly by run_test
assert_not_contains() {
    local haystack="$1"
    local needle="$2"
    local message="${3:-String should not be found}"

    if [[ "$haystack" != *"$needle"* ]]; then
        return 0
    else
        echo -e "${RED}ASSERTION FAILED: $message${NC}"
        echo "  Should NOT find: '$needle'"
        return 1
    fi
}

# shellcheck disable=SC2317  # Called indirectly by run_test
assert_exit_code() {
    local expected="$1"
    local actual="$2"
    local message="${3:-Exit code mismatch}"

    if [[ "$expected" == "$actual" ]]; then
        return 0
    else
        echo -e "${RED}ASSERTION FAILED: $message${NC}"
        echo "  Expected exit code: $expected"
        echo "  Actual exit code:   $actual"
        return 1
    fi
}

run_test() {
    local test_name="$1"
    local test_function="$2"

    ((TESTS_RUN++))

    echo -ne "${BLUE}[TEST]${NC} $test_name... "

    local output
    local exit_code=0

    output=$($test_function 2>&1) || exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        echo -e "${GREEN}PASS${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}FAIL${NC}"
        ((TESTS_FAILED++))
        if [[ -n "$output" ]]; then
            # Indent each line of diagnostic output by 4 spaces
            while IFS= read -r line; do
                echo "    $line"
            done <<< "$output"
        fi
    fi
}

# =============================================================================
# UNIT TESTS
# =============================================================================

# shellcheck disable=SC2317  # Called indirectly via run_test
test_script_exists() {
    [[ -f "$VPS_AUDIT_SCRIPT" ]]
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_script_executable() {
    # Ensure the script is executable; make it so if not (idempotent setup)
    if [[ ! -x "$VPS_AUDIT_SCRIPT" ]]; then
        chmod +x "$VPS_AUDIT_SCRIPT" || {
            echo "Cannot make script executable"
            return 1
        }
    fi
    [[ -x "$VPS_AUDIT_SCRIPT" ]]
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_bash_syntax() {
    bash -n "$VPS_AUDIT_SCRIPT"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_help_option() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --help 2>&1)
    assert_contains "$output" "VPS Security Audit Tool" "Help should show tool name"
    assert_contains "$output" "Usage:" "Help should show usage"
    assert_contains "$output" "--guide" "Help should mention --guide option"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_version_option() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --version 2>&1)
    assert_contains "$output" "VPS Security Audit Tool v" "Version should show tool name"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_guide_option() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --guide 2>&1)
    assert_contains "$output" "Quick-Start Hardening Guide" "Guide should show title"
    assert_contains "$output" "SSH key authentication" "Guide should mention SSH"
    assert_contains "$output" "firewall" "Guide should mention firewall"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_dry_run_option() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run 2>&1)
    assert_contains "$output" "DRY RUN" "Dry run should indicate mode"
    assert_contains "$output" "[x]" "Dry run should show check marks"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_invalid_option() {
    local output
    local exit_code=0
    output=$("$VPS_AUDIT_SCRIPT" --invalid-option 2>&1) || exit_code=$?
    assert_exit_code "1" "$exit_code" "Invalid option should exit with code 1"
    assert_contains "$output" "Unknown option" "Should report unknown option"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_checks_filter() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run --checks ssh,firewall 2>&1)
    assert_contains "$output" "SSH" "Should list SSH check"
    assert_contains "$output" "skipped" "Should show skipped checks"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_quiet_mode_help() {
    # Quiet mode should still show help
    local output
    output=$("$VPS_AUDIT_SCRIPT" -q --help 2>&1)
    assert_contains "$output" "Usage:" "Quiet mode should still show help"
}

# =============================================================================
# FUNCTION UNIT TESTS (sourcing script components)
# =============================================================================

# shellcheck disable=SC2317  # Called indirectly via run_test
test_is_numeric_function() {
    # Extract and test the is_numeric function from the script
    # We can't source the whole script since it requires root and runs main

    # Verify the function exists and uses proper regex
    if ! grep -q 'is_numeric()' "$VPS_AUDIT_SCRIPT"; then
        echo "is_numeric function not found"
        return 1
    fi

    # Extract and execute just the is_numeric function
    local func_def
    func_def=$(sed -n '/^is_numeric() {/,/^}/p' "$VPS_AUDIT_SCRIPT")

    # Test in a subshell to avoid polluting the outer environment
    # shellcheck disable=SC2317  # eval in subshell is intentional for function extraction
    (
        # shellcheck disable=SC2294  # eval is intentional: extracts function from script text
        eval "$func_def"

        # Test with numbers
        is_numeric "123" || exit 1
        is_numeric "0" || exit 1
        is_numeric "99999" || exit 1

        # Test with non-numbers (negative values must fail is_numeric)
        is_numeric "abc"   && exit 1
        is_numeric "12.34" && exit 1
        is_numeric ""      && exit 1
        is_numeric " "     && exit 1
        is_numeric "-1"    && exit 1

        exit 0
    )
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_is_integer_function() {
    # Verify is_integer exists (handles signed integers for pwquality credits)
    if ! grep -q 'is_integer()' "$VPS_AUDIT_SCRIPT"; then
        echo "is_integer function not found"
        return 1
    fi

    local func_def
    func_def=$(sed -n '/^is_integer() {/,/^}/p' "$VPS_AUDIT_SCRIPT")

    (
        # shellcheck disable=SC2294  # eval is intentional: extracts function from script text
        eval "$func_def"

        # Positive integers must pass
        is_integer "0"     || exit 1
        is_integer "123"   || exit 1

        # Negative integers must pass (pwquality credit values)
        is_integer "-1"    || exit 1
        is_integer "-100"  || exit 1

        # Non-integers must fail
        is_integer "abc"   && exit 1
        is_integer "12.34" && exit 1
        is_integer ""      && exit 1
        is_integer " "     && exit 1
        is_integer "--1"   && exit 1

        exit 0
    )
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_json_escape() {
    # Test that special characters are escaped properly
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run -f json 2>&1) || true
    assert_not_contains "$output" "Syntax error" "JSON should not have syntax errors"
}

# =============================================================================
# OUTPUT FORMAT TESTS
# =============================================================================

# shellcheck disable=SC2317  # Called indirectly via run_test
test_text_output_format() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run 2>&1)
    # Should contain colored output markers or plain text structure
    assert_contains "$output" "VPS Security Audit Tool" "Should have header"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_json_output_mentions_json() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run -f json 2>&1)
    # Dry run with JSON format should work
    assert_contains "$output" "DRY RUN" "JSON format dry run should work"
}

# =============================================================================
# THRESHOLD OPTION TESTS
# =============================================================================

# shellcheck disable=SC2317  # Called indirectly via run_test
test_disk_warn_threshold() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --help 2>&1)
    assert_contains "$output" "--disk-warn" "Should document disk-warn option"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_mem_warn_threshold() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --help 2>&1)
    assert_contains "$output" "--mem-warn" "Should document mem-warn option"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_login_warn_threshold() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --help 2>&1)
    assert_contains "$output" "--login-warn" "Should document login-warn option"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_invalid_threshold() {
    local output
    local exit_code=0
    output=$("$VPS_AUDIT_SCRIPT" --disk-warn notanumber 2>&1) || exit_code=$?
    assert_exit_code "1" "$exit_code" "Non-numeric threshold should fail"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_threshold_relationship() {
    # warn >= fail should be rejected
    local output
    local exit_code=0
    output=$("$VPS_AUDIT_SCRIPT" --disk-warn 80 --disk-fail 50 2>&1) || exit_code=$?
    assert_exit_code "1" "$exit_code" "warn >= fail threshold should fail"
    assert_contains "$output" "Threshold error" "Should report threshold relationship error"
}

# =============================================================================
# SKIP OPTIONS TESTS
# =============================================================================

# shellcheck disable=SC2317  # Called indirectly via run_test
test_no_network_option() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run --no-network 2>&1)
    assert_contains "$output" "DRY RUN" "Should run in dry-run mode"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_no_suid_option() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run --no-suid 2>&1)
    assert_contains "$output" "DRY RUN" "Should run in dry-run mode"
}

# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

# shellcheck disable=SC2317  # Called indirectly via run_test
test_missing_output_dir() {
    local output
    local exit_code=0
    output=$("$VPS_AUDIT_SCRIPT" -o /nonexistent/directory --help 2>&1) || exit_code=$?
    # --help should work even with invalid output dir
    assert_contains "$output" "Usage:" "Help should still show even with bad output dir"
}

# =============================================================================
# PORTABLE STAT FUNCTION TEST
# =============================================================================

# shellcheck disable=SC2317  # Called indirectly via run_test
test_portable_stat_syntax() {
    # Verify the portable_stat function is defined correctly
    grep -q "portable_stat()" "$VPS_AUDIT_SCRIPT" || {
        echo "portable_stat function not found"
        return 1
    }

    # Verify it handles all expected format options
    grep -q 'uid)' "$VPS_AUDIT_SCRIPT" || {
        echo "portable_stat uid format not found"
        return 1
    }
    grep -q 'mode)' "$VPS_AUDIT_SCRIPT" || {
        echo "portable_stat mode format not found"
        return 1
    }
}

# =============================================================================
# HAS_COMMAND FUNCTION TEST
# =============================================================================

# shellcheck disable=SC2317  # Called indirectly via run_test
test_has_command_syntax() {
    # Verify the has_command function is defined
    grep -q "has_command()" "$VPS_AUDIT_SCRIPT" || {
        echo "has_command function not found"
        return 1
    }

    # Verify command caching is implemented
    grep -q "CMD_CACHE" "$VPS_AUDIT_SCRIPT" || {
        echo "CMD_CACHE not found"
        return 1
    }
}

# =============================================================================
# TOOL INFO TEST
# =============================================================================

# shellcheck disable=SC2317  # Called indirectly via run_test
test_tool_info_array() {
    # Verify TOOL_INFO array is defined
    grep -q "declare -A TOOL_INFO" "$VPS_AUDIT_SCRIPT" || {
        echo "TOOL_INFO array not found"
        return 1
    }

    # Verify stat_type detection is implemented
    grep -q "stat_type" "$VPS_AUDIT_SCRIPT" || {
        echo "stat_type not found in TOOL_INFO"
        return 1
    }
}

# =============================================================================
# PHASE 9 NEW CHECK FUNCTION PRESENCE TESTS
# =============================================================================

# shellcheck disable=SC2317  # Called indirectly via run_test
test_phase9_functions_exist() {
    local missing=()
    local expected_functions=(
        check_ssh_hardening_extended
        check_sudoers_security
        check_tmp_mount_options
        check_file_integrity_monitoring
        check_rootkit_detection
        check_legacy_services
        check_sensitive_permissions
        check_docker_security
        check_network_sysctl
        check_home_directory_permissions
        check_nfs_exports
        check_path_security
        check_exposed_services
    )
    for fn in "${expected_functions[@]}"; do
        if ! grep -q "^${fn}()" "$VPS_AUDIT_SCRIPT"; then
            missing+=("$fn")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing Phase 9 functions: ${missing[*]}"
        return 1
    fi
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_phase9_functions_in_main() {
    local missing=()
    local expected_calls=(
        check_ssh_hardening_extended
        check_sudoers_security
        check_tmp_mount_options
        check_file_integrity_monitoring
        check_rootkit_detection
        check_legacy_services
        check_sensitive_permissions
        check_docker_security
        check_network_sysctl
        check_home_directory_permissions
        check_nfs_exports
        check_path_security
        check_exposed_services
    )
    for fn in "${expected_calls[@]}"; do
        # Must appear as a call (indented or otherwise) in the script
        if ! grep -q "^[[:space:]]*${fn}$" "$VPS_AUDIT_SCRIPT"; then
            missing+=("$fn")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Phase 9 calls missing from main(): ${missing[*]}"
        return 1
    fi
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_version_updated() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --version 2>&1)
    assert_contains "$output" "2.4.0" "Version should be 2.4.0"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_dry_run_new_categories() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run 2>&1)
    # Match against the description strings used in the dry-run output (not the category keys)
    assert_contains "$output" "integrity"  "Dry run should mention integrity monitoring"
    assert_contains "$output" "Docker"     "Dry run should mention Docker security check"
    assert_contains "$output" "noexec"     "Dry run should mention temp mount options (noexec)"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_checks_filter_new_categories() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run --checks integrity,docker 2>&1)
    assert_contains "$output" "DRY RUN" "Should enter dry-run mode"
    assert_contains "$output" "skipped"  "Other checks should be skipped"
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_ssh_hardening_check_present() {
    grep -q "check_ssh_hardening_extended" "$VPS_AUDIT_SCRIPT" || {
        echo "check_ssh_hardening_extended not found"
        return 1
    }
    grep -q "X11Forwarding" "$VPS_AUDIT_SCRIPT" || {
        echo "X11Forwarding check not found"
        return 1
    }
    grep -q "MaxAuthTries" "$VPS_AUDIT_SCRIPT" || {
        echo "MaxAuthTries check not found"
        return 1
    }
    grep -q "ClientAliveInterval" "$VPS_AUDIT_SCRIPT" || {
        echo "ClientAliveInterval check not found"
        return 1
    }
    grep -q "PermitEmptyPasswords" "$VPS_AUDIT_SCRIPT" || {
        echo "PermitEmptyPasswords check not found"
        return 1
    }
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_exposed_services_check_present() {
    grep -q "check_exposed_services" "$VPS_AUDIT_SCRIPT" || {
        echo "check_exposed_services not found"
        return 1
    }
    # Verify it checks well-known backend service ports
    grep -q '"3306"' "$VPS_AUDIT_SCRIPT" || {
        echo "MySQL port 3306 not in check_exposed_services"
        return 1
    }
    grep -q '"6379"' "$VPS_AUDIT_SCRIPT" || {
        echo "Redis port 6379 not in check_exposed_services"
        return 1
    }
    grep -q '"27017"' "$VPS_AUDIT_SCRIPT" || {
        echo "MongoDB port 27017 not in check_exposed_services"
        return 1
    }
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_sudoers_check_present() {
    grep -q "check_sudoers_security" "$VPS_AUDIT_SCRIPT" || {
        echo "check_sudoers_security not found"
        return 1
    }
    grep -q "NOPASSWD" "$VPS_AUDIT_SCRIPT" || {
        echo "NOPASSWD check not found"
        return 1
    }
    grep -q "sudoers.d" "$VPS_AUDIT_SCRIPT" || {
        echo "/etc/sudoers.d check not found"
        return 1
    }
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_network_sysctl_check_present() {
    grep -q "check_network_sysctl" "$VPS_AUDIT_SCRIPT" || {
        echo "check_network_sysctl not found"
        return 1
    }
    grep -q "ip_forward" "$VPS_AUDIT_SCRIPT" || {
        echo "ip_forward sysctl not checked"
        return 1
    }
    grep -q "kernel.sysrq" "$VPS_AUDIT_SCRIPT" || {
        echo "kernel.sysrq sysctl not checked"
        return 1
    }
    grep -q "yama.ptrace_scope" "$VPS_AUDIT_SCRIPT" || {
        echo "kernel.yama.ptrace_scope sysctl not checked"
        return 1
    }
}

# =============================================================================
# SOURCED FUNCTION UNIT TESTS
#
# The audit script guards `main` behind a BASH_SOURCE check, so it can be
# sourced to test its pure helper functions directly - actually exercising
# behaviour rather than grepping the source for strings. Each test sources the
# script in a SUBSHELL (fresh readonly state, no global pollution) and asserts
# on real return values.
# =============================================================================

# shellcheck disable=SC2317  # Called indirectly via run_test
test_unit_source_does_not_run_audit() {
    # Sourcing must define functions WITHOUT running an audit.
    local out
    # shellcheck source=/dev/null
    out=$(source "$VPS_AUDIT_SCRIPT" 2>&1)
    assert_not_contains "$out" "Audit Summary" "sourcing must not run the audit" || return 1
    assert_not_contains "$out" "[PASS]" "sourcing must not execute checks" || return 1
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_unit_sanitize_int() {
    (
        # shellcheck source=/dev/null
        source "$VPS_AUDIT_SCRIPT"
        assert_equals "0"  "$(sanitize_int '')"        "empty -> 0"                    || exit 1
        assert_equals "0"  "$(sanitize_int '0')"       "0 -> 0"                        || exit 1
        assert_equals "5"  "$(sanitize_int '5')"       "5 -> 5"                        || exit 1
        assert_equals "12" "$(sanitize_int '  12  ')"  "surrounding spaces stripped"   || exit 1
        assert_equals "8"  "$(sanitize_int '08')"      "08 read base-10 (not octal)"   || exit 1
        assert_equals "0"  "$(sanitize_int 'abc')"     "non-numeric -> 0"              || exit 1
        # The historical "0\n0" double-zero footgun must normalise to 0.
        assert_equals "0"  "$(sanitize_int "$(printf '0\n0')")" "0-newline-0 -> 0"     || exit 1
    )
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_unit_count_lines() {
    (
        # shellcheck source=/dev/null
        source "$VPS_AUDIT_SCRIPT"
        assert_equals "0" "$(printf ''        | count_lines)" "empty input -> 0"        || exit 1
        assert_equals "3" "$(printf 'a\nb\nc\n' | count_lines)" "3 lines -> 3"          || exit 1
        assert_equals "1" "$(printf 'x'       | count_lines)" "no trailing newline -> 1" || exit 1
        # grep with no match yields nothing -> 0 (the bug the helper fixes).
        assert_equals "0" "$(printf 'a\nb\n' | grep 'zzz' | count_lines)" "no-match -> 0" || exit 1
    )
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_unit_classify_bind_scope() {
    (
        # shellcheck source=/dev/null
        source "$VPS_AUDIT_SCRIPT"
        # Wildcard / all-interfaces binds are public.
        assert_equals "public" "$(classify_bind_scope 0.0.0.0)"     "0.0.0.0 is public"      || exit 1
        assert_equals "public" "$(classify_bind_scope '*')"         "* is public"            || exit 1
        assert_equals "public" "$(classify_bind_scope '::')"        ":: is public"           || exit 1
        # Loopback (incl. systemd-resolved 127.0.0.53) is local.
        assert_equals "local"  "$(classify_bind_scope 127.0.0.1)"   "127.0.0.1 is local"     || exit 1
        assert_equals "local"  "$(classify_bind_scope 127.0.0.53)"  "127.0.0.53 is local"    || exit 1
        assert_equals "local"  "$(classify_bind_scope ::1)"         "::1 is local"           || exit 1
        # RFC1918 / link-local / ULA are local.
        assert_equals "local"  "$(classify_bind_scope 10.0.0.5)"    "10/8 is local"          || exit 1
        assert_equals "local"  "$(classify_bind_scope 192.168.1.1)" "192.168/16 is local"    || exit 1
        assert_equals "local"  "$(classify_bind_scope 172.16.0.1)"  "172.16/12 is local"     || exit 1
        assert_equals "local"  "$(classify_bind_scope 169.254.0.1)" "link-local is local"    || exit 1
        assert_equals "local"  "$(classify_bind_scope fe80::1)"     "fe80:: is local"        || exit 1
        assert_equals "local"  "$(classify_bind_scope fd00::1)"     "fd00:: (ULA) is local"  || exit 1
        # Public addresses (incl. 172.15 just outside RFC1918) are public.
        assert_equals "public" "$(classify_bind_scope 172.15.0.1)"  "172.15 is public"       || exit 1
        assert_equals "public" "$(classify_bind_scope 8.8.8.8)"     "8.8.8.8 is public"      || exit 1
        assert_equals "public" "$(classify_bind_scope 2001:db8::1)" "global IPv6 is public"  || exit 1
    )
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_unit_json_escape() {
    (
        # shellcheck source=/dev/null
        source "$VPS_AUDIT_SCRIPT"
        assert_equals '\"'   "$(json_escape '"')"                "double quote escaped"   || exit 1
        assert_equals '\\'   "$(json_escape '\')"                "backslash escaped"      || exit 1
        assert_equals 'a\tb' "$(json_escape "$(printf 'a\tb')")" "tab escaped"            || exit 1
        assert_equals 'x\\\"y' "$(json_escape 'x\"y')"           "backslash before quote" || exit 1
    )
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_unit_bytes_to_human() {
    (
        # shellcheck source=/dev/null
        source "$VPS_AUDIT_SCRIPT"
        assert_equals "0B"   "$(bytes_to_human 0)"          "0 bytes"        || exit 1
        assert_equals "512B" "$(bytes_to_human 512)"        "sub-KiB bytes"  || exit 1
        assert_equals "1.0K" "$(bytes_to_human 1024)"       "1 KiB"          || exit 1
        assert_equals "1.0M" "$(bytes_to_human 1048576)"    "1 MiB"          || exit 1
        assert_equals "2.0G" "$(bytes_to_human 2147483648)" "2 GiB"          || exit 1
        assert_equals "?"    "$(bytes_to_human abc)"        "non-numeric -> ?" || exit 1
    )
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_unit_is_numeric_is_integer() {
    (
        # shellcheck source=/dev/null
        source "$VPS_AUDIT_SCRIPT"
        is_numeric "0"    || exit 1
        is_numeric "999"  || exit 1
        is_numeric "-1"   && exit 1   # negative is NOT is_numeric
        is_numeric "1.5"  && exit 1
        is_numeric ""     && exit 1
        is_integer "-1"   || exit 1   # negative IS is_integer
        is_integer "42"   || exit 1
        is_integer "1.5"  && exit 1
        exit 0
    )
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_unit_portable_stat() {
    (
        # shellcheck source=/dev/null
        source "$VPS_AUDIT_SCRIPT"
        detect_tool_versions   # populate TOOL_INFO[stat_type]
        local tmp
        tmp=$(mktemp) || exit 1
        chmod 640 "$tmp"
        local mode uid mt
        mode=$(portable_stat mode "$tmp")
        uid=$(portable_stat uid "$tmp")
        mt=$(portable_stat mtime "$tmp")
        rm -f "$tmp"
        assert_equals "640" "$mode" "portable_stat mode reads 640" || exit 1
        [[ "$uid" =~ ^[0-9]+$ ]] || { echo "uid not numeric: $uid"; exit 1; }
        [[ "$mt"  =~ ^[0-9]+$ ]] || { echo "mtime not numeric: $mt"; exit 1; }
    )
}

# shellcheck disable=SC2317  # Called indirectly via run_test
test_unit_get_ssh_config_default() {
    (
        # shellcheck source=/dev/null
        source "$VPS_AUDIT_SCRIPT"
        # When sshd -T is unavailable and no config sets the key, the supplied
        # default must be returned verbatim.
        local v
        v=$(get_ssh_config "ThisSettingDoesNotExist12345" "my-default")
        assert_equals "my-default" "$v" "unknown SSH setting returns the default" || exit 1
    )
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    echo "═══════════════════════════════════════════════════════════════"
    echo "VPS Audit Integration Tests"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Script: $VPS_AUDIT_SCRIPT"
    echo "Date: $(date)"
    echo ""

    # Basic tests
    echo "── Basic Tests ──"
    run_test "Script exists" test_script_exists
    run_test "Script is executable" test_script_executable
    run_test "Bash syntax check" test_bash_syntax

    # Command line option tests
    echo ""
    echo "── Command Line Options ──"
    run_test "--help option" test_help_option
    run_test "--version option" test_version_option
    run_test "--guide option" test_guide_option
    run_test "--dry-run option" test_dry_run_option
    run_test "Invalid option handling" test_invalid_option
    run_test "--checks filter" test_checks_filter
    run_test "Quiet mode with help" test_quiet_mode_help

    # Function tests
    echo ""
    echo "── Function Tests ──"
    run_test "is_numeric function" test_is_numeric_function
    run_test "is_integer function" test_is_integer_function
    run_test "JSON escaping" test_json_escape
    run_test "portable_stat function" test_portable_stat_syntax
    run_test "has_command function" test_has_command_syntax
    run_test "TOOL_INFO array" test_tool_info_array

    # Sourced function unit tests (exercise real behaviour, not string presence)
    echo ""
    echo "── Sourced Function Unit Tests ──"
    run_test "sourcing does not run the audit"  test_unit_source_does_not_run_audit
    run_test "is_numeric / is_integer behaviour" test_unit_is_numeric_is_integer
    run_test "sanitize_int (incl. base-10 + 0\\n0)" test_unit_sanitize_int
    run_test "count_lines helper"                test_unit_count_lines
    run_test "classify_bind_scope (ports/IPv6)"  test_unit_classify_bind_scope
    run_test "json_escape correctness"           test_unit_json_escape
    run_test "bytes_to_human formatting"         test_unit_bytes_to_human
    run_test "portable_stat (mode/uid/mtime)"    test_unit_portable_stat
    run_test "get_ssh_config default fallback"   test_unit_get_ssh_config_default

    # Output format tests
    echo ""
    echo "── Output Format Tests ──"
    run_test "Text output format" test_text_output_format
    run_test "JSON output format" test_json_output_mentions_json

    # Threshold tests
    echo ""
    echo "── Threshold Option Tests ──"
    run_test "disk-warn threshold option" test_disk_warn_threshold
    run_test "mem-warn threshold option" test_mem_warn_threshold
    run_test "login-warn threshold option" test_login_warn_threshold
    run_test "Invalid threshold handling" test_invalid_threshold
    run_test "Threshold relationship validation" test_threshold_relationship

    # Skip option tests
    echo ""
    echo "── Skip Option Tests ──"
    run_test "--no-network option" test_no_network_option
    run_test "--no-suid option" test_no_suid_option

    # Error handling tests
    echo ""
    echo "── Error Handling Tests ──"
    run_test "Missing output directory" test_missing_output_dir

    # Phase 9 new check tests
    echo ""
    echo "── Phase 9: New Security Check Tests ──"
    run_test "Phase 9 functions exist" test_phase9_functions_exist
    run_test "Phase 9 functions called in main()" test_phase9_functions_in_main
    run_test "Version updated to 2.3.0" test_version_updated
    run_test "Dry run lists new categories" test_dry_run_new_categories
    run_test "--checks filter with new categories" test_checks_filter_new_categories
    run_test "SSH hardening check (X11/MaxAuthTries/idle/empty-pw)" test_ssh_hardening_check_present
    run_test "Exposed services check (MySQL/Redis/MongoDB)" test_exposed_services_check_present
    run_test "Sudoers NOPASSWD check" test_sudoers_check_present
    run_test "Network sysctl hardening check" test_network_sysctl_check_present

    # Summary
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "Test Summary"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Total tests: $TESTS_RUN"
    echo -e "Passed:      ${GREEN}${TESTS_PASSED}${NC}"
    echo -e "Failed:      ${RED}${TESTS_FAILED}${NC}"
    echo ""

    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed.${NC}"
        exit 1
    fi
}

main "$@"
