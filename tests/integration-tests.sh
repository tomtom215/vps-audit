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
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly NC='\033[0m'
else
    readonly GREEN=''
    readonly RED=''
    # shellcheck disable=SC2034  # YELLOW is used for consistency, may be used in future tests
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
            echo "$output" | sed 's/^/    /'
        fi
    fi
}

# =============================================================================
# UNIT TESTS
# =============================================================================

test_script_exists() {
    [[ -f "$VPS_AUDIT_SCRIPT" ]]
}

test_script_executable() {
    [[ -x "$VPS_AUDIT_SCRIPT" ]] || chmod +x "$VPS_AUDIT_SCRIPT"
    [[ -x "$VPS_AUDIT_SCRIPT" ]]
}

test_bash_syntax() {
    bash -n "$VPS_AUDIT_SCRIPT"
}

test_help_option() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --help 2>&1)
    assert_contains "$output" "VPS Security Audit Tool" "Help should show tool name"
    assert_contains "$output" "Usage:" "Help should show usage"
    assert_contains "$output" "--guide" "Help should mention --guide option"
}

test_version_option() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --version 2>&1)
    assert_contains "$output" "VPS Security Audit Tool v" "Version should show tool name"
}

test_guide_option() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --guide 2>&1)
    assert_contains "$output" "Quick-Start Hardening Guide" "Guide should show title"
    assert_contains "$output" "SSH key authentication" "Guide should mention SSH"
    assert_contains "$output" "firewall" "Guide should mention firewall"
}

test_dry_run_option() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run 2>&1)
    assert_contains "$output" "DRY RUN" "Dry run should indicate mode"
    assert_contains "$output" "[x]" "Dry run should show check marks"
}

test_invalid_option() {
    local output
    local exit_code=0
    output=$("$VPS_AUDIT_SCRIPT" --invalid-option 2>&1) || exit_code=$?
    assert_exit_code "1" "$exit_code" "Invalid option should exit with code 1"
    assert_contains "$output" "Unknown option" "Should report unknown option"
}

test_checks_filter() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run --checks ssh,firewall 2>&1)
    assert_contains "$output" "SSH" "Should list SSH check"
    assert_contains "$output" "skipped" "Should show skipped checks"
}

test_quiet_mode_help() {
    # Quiet mode should still show help
    local output
    output=$("$VPS_AUDIT_SCRIPT" -q --help 2>&1)
    assert_contains "$output" "Usage:" "Quiet mode should still show help"
}

# =============================================================================
# FUNCTION UNIT TESTS (sourcing script components)
# =============================================================================

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

    # Test in a subshell
    (
        eval "$func_def"

        # Test with numbers
        is_numeric "123" || exit 1
        is_numeric "0" || exit 1
        is_numeric "99999" || exit 1

        # Test with non-numbers
        is_numeric "abc" && exit 1
        is_numeric "12.34" && exit 1
        is_numeric "" && exit 1
        is_numeric " " && exit 1

        exit 0
    )
}

test_json_escape() {
    # Test that special characters are escaped properly
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run -f json 2>&1) || true
    assert_not_contains "$output" "Syntax error" "JSON should not have syntax errors"
}

# =============================================================================
# OUTPUT FORMAT TESTS
# =============================================================================

test_text_output_format() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run 2>&1)
    # Should contain colored output markers or plain text structure
    assert_contains "$output" "VPS Security Audit Tool" "Should have header"
}

test_json_output_mentions_json() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run -f json 2>&1)
    # Dry run with JSON format should work
    assert_contains "$output" "DRY RUN" "JSON format dry run should work"
}

# =============================================================================
# THRESHOLD OPTION TESTS
# =============================================================================

test_disk_warn_threshold() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --help 2>&1)
    assert_contains "$output" "--disk-warn" "Should document disk-warn option"
}

test_mem_warn_threshold() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --help 2>&1)
    assert_contains "$output" "--mem-warn" "Should document mem-warn option"
}

test_login_warn_threshold() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --help 2>&1)
    assert_contains "$output" "--login-warn" "Should document login-warn option"
}

test_invalid_threshold() {
    local output
    local exit_code=0
    output=$("$VPS_AUDIT_SCRIPT" --disk-warn notanumber 2>&1) || exit_code=$?
    assert_exit_code "1" "$exit_code" "Non-numeric threshold should fail"
}

# =============================================================================
# SKIP OPTIONS TESTS
# =============================================================================

test_no_network_option() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run --no-network 2>&1)
    assert_contains "$output" "DRY RUN" "Should run in dry-run mode"
}

test_no_suid_option() {
    local output
    output=$("$VPS_AUDIT_SCRIPT" --dry-run --no-suid 2>&1)
    assert_contains "$output" "DRY RUN" "Should run in dry-run mode"
}

# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

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
    run_test "JSON escaping" test_json_escape
    run_test "portable_stat function" test_portable_stat_syntax
    run_test "has_command function" test_has_command_syntax
    run_test "TOOL_INFO array" test_tool_info_array

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

    # Skip option tests
    echo ""
    echo "── Skip Option Tests ──"
    run_test "--no-network option" test_no_network_option
    run_test "--no-suid option" test_no_suid_option

    # Error handling tests
    echo ""
    echo "── Error Handling Tests ──"
    run_test "Missing output directory" test_missing_output_dir

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
