#!/usr/bin/env bash
#
# VPS Audit Test Matrix
# Multi-distribution testing framework using Docker
#
# This script tests vps-audit.sh across multiple Linux distributions
# to ensure compatibility and proper behavior.
#

set -o pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly VPS_AUDIT_SCRIPT="${SCRIPT_DIR}/vps-audit.sh"
readonly TEST_RESULTS_DIR="${SCRIPT_DIR}/test-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly TIMESTAMP

# Distribution images to test (tag:name for display)
declare -A DISTROS=(
    ["ubuntu:22.04"]="Ubuntu 22.04 LTS"
    ["ubuntu:24.04"]="Ubuntu 24.04 LTS"
    ["debian:11"]="Debian 11 (Bullseye)"
    ["debian:12"]="Debian 12 (Bookworm)"
    ["rockylinux:9"]="Rocky Linux 9"
    ["almalinux:9"]="AlmaLinux 9"
    ["fedora:39"]="Fedora 39"
    ["fedora:40"]="Fedora 40"
    ["alpine:3.19"]="Alpine Linux 3.19"
    ["alpine:3.20"]="Alpine Linux 3.20"
    ["archlinux:latest"]="Arch Linux"
    ["opensuse/leap:15.5"]="openSUSE Leap 15.5"
)

# Colors for output
if [[ -t 1 ]]; then
    readonly GREEN='\033[0;32m'
    readonly RED='\033[0;31m'
    readonly YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m'
    readonly BOLD='\033[1m'
    readonly NC='\033[0m'
else
    readonly GREEN='' RED='' YELLOW='' BLUE='' BOLD='' NC=''
fi

# Test results
declare -A TEST_RESULTS=()
declare -i TOTAL_TESTS=0
declare -i PASSED_TESTS=0
declare -i FAILED_TESTS=0
declare -i SKIPPED_TESTS=0

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[PASS]${NC} $*"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $*"
}

# Check if Docker is available
check_docker() {
    if ! command -v docker &>/dev/null; then
        log_error "Docker is not installed. Please install Docker to run tests."
        exit 1
    fi

    if ! docker info &>/dev/null; then
        log_error "Docker daemon is not running or you don't have permission."
        exit 1
    fi

    log_info "Docker is available"
}

# Create test results directory
setup_results_dir() {
    mkdir -p "${TEST_RESULTS_DIR}"
    log_info "Test results will be saved to: ${TEST_RESULTS_DIR}"
}

# =============================================================================
# TEST FUNCTIONS
# =============================================================================

# Generate distro-specific setup commands
get_setup_commands() {
    local image="$1"

    case "$image" in
        ubuntu:*|debian:*)
            # Keep stdout quiet but show stderr for debugging
            echo "apt-get update -qq && apt-get install -y -qq procps iproute2 net-tools curl openssh-server hostname coreutils findutils >/dev/null"
            ;;
        rockylinux:*|almalinux:*|fedora:*)
            # Keep stdout quiet but show stderr for debugging
            echo "dnf install -y -q procps-ng iproute net-tools curl openssh-server hostname coreutils findutils >/dev/null"
            ;;
        alpine:*)
            # Alpine needs bash explicitly, keep stdout quiet but show stderr
            echo "apk add --no-cache bash coreutils findutils grep gawk sed procps iproute2 curl openssh >/dev/null"
            ;;
        archlinux:*)
            # Arch needs explicit refresh, keep stdout quiet but show stderr
            echo "pacman -Sy --noconfirm procps-ng iproute2 net-tools curl openssh coreutils findutils which >/dev/null"
            ;;
        opensuse/*:*)
            # openSUSE setup, keep stdout quiet but show stderr
            echo "zypper -n install -y procps iproute2 net-tools curl openssh hostname coreutils findutils >/dev/null"
            ;;
        *)
            echo "echo 'No setup needed'"
            ;;
    esac
}

# Run tests on a specific distribution
test_distro() {
    local image="$1"
    local display_name="$2"
    local result_file="${TEST_RESULTS_DIR}/${image//[:\/]/_}_${TIMESTAMP}.log"

    ((TOTAL_TESTS++))

    echo ""
    log_info "Testing on ${BOLD}${display_name}${NC} (${image})"
    echo "─────────────────────────────────────────────"

    # Check if image exists or can be pulled
    if ! docker pull "$image" &>/dev/null; then
        log_skip "Could not pull image: $image"
        TEST_RESULTS[$image]="SKIPPED"
        ((SKIPPED_TESTS++))
        return 1
    fi

    local setup_cmd
    setup_cmd=$(get_setup_commands "$image")

    # Create test script that will run inside container
    local test_script
    test_script=$(cat << 'INNER_SCRIPT'
#!/bin/bash
set -e

# Show environment info for debugging
echo "=== Environment Info ==="
echo "Bash version: ${BASH_VERSION:-unknown}"
echo "Current user: $(whoami)"
echo "Working directory: $(pwd)"
echo ""

# Run syntax check
echo "=== Running bash -n syntax check ==="
if bash -n /test/vps-audit.sh; then
    echo "SYNTAX: PASS"
else
    echo "SYNTAX: FAIL"
    exit 1
fi

# Run --help test
echo ""
echo "=== Running --help test ==="
set +e
help_output=$(/test/vps-audit.sh --help 2>&1)
help_exit=$?
set -e
if [[ $help_exit -eq 0 ]]; then
    echo "HELP: PASS"
else
    echo "HELP: FAIL (exit code: $help_exit)"
    echo "Output: $help_output"
    exit 1
fi

# Run --version test
echo ""
echo "=== Running --version test ==="
set +e
version_output=$(/test/vps-audit.sh --version 2>&1)
version_exit=$?
set -e
if echo "$version_output" | grep -q "VPS Security Audit Tool"; then
    echo "VERSION: PASS"
else
    echo "VERSION: FAIL (exit code: $version_exit)"
    echo "Output: $version_output"
    exit 1
fi

# Run --dry-run test
echo ""
echo "=== Running --dry-run test ==="
set +e
dryrun_output=$(/test/vps-audit.sh --dry-run 2>&1)
dryrun_exit=$?
set -e
if echo "$dryrun_output" | grep -q "DRY RUN"; then
    echo "DRY_RUN: PASS"
else
    echo "DRY_RUN: FAIL (exit code: $dryrun_exit)"
    echo "--- Begin --dry-run output ---"
    echo "$dryrun_output"
    echo "--- End --dry-run output ---"
    exit 1
fi

# Run --guide test
echo ""
echo "=== Running --guide test ==="
set +e
guide_output=$(/test/vps-audit.sh --guide 2>&1)
guide_exit=$?
set -e
if echo "$guide_output" | grep -q "Quick-Start"; then
    echo "GUIDE: PASS"
else
    echo "GUIDE: FAIL (exit code: $guide_exit)"
    echo "Output: $guide_output"
    exit 1
fi

# Run actual audit (may have failures due to container environment, but should not crash)
echo ""
echo "=== Running full audit ==="
set +e
audit_output=$(/test/vps-audit.sh --no-suid --no-network -q -f json -o /tmp 2>&1)
exit_code=$?
set -e

# Any exit code is acceptable as long as the script completes (0, 1, or 2)
if [[ $exit_code -le 2 ]]; then
    echo "FULL_AUDIT: PASS (exit code: $exit_code)"
else
    echo "FULL_AUDIT: FAIL (exit code: $exit_code)"
    echo "--- Begin audit output ---"
    echo "$audit_output"
    echo "--- End audit output ---"
    exit 1
fi

# Check JSON output was created
echo ""
echo "=== Checking JSON output ==="
json_file=""
for f in /tmp/vps-audit-report-*.json; do
    if [[ -f "$f" ]]; then
        json_file="$f"
        break
    fi
done

if [[ -n "$json_file" ]]; then
    if grep -q '"version"' "$json_file" && grep -q '"checks"' "$json_file"; then
        echo "JSON_OUTPUT: PASS"
    else
        echo "JSON_OUTPUT: FAIL (invalid JSON structure)"
        echo "JSON file contents:"
        head -50 "$json_file"
        exit 1
    fi
else
    echo "JSON_OUTPUT: WARN (no JSON file found, may be expected)"
fi

echo ""
echo "=== All tests completed successfully ==="
INNER_SCRIPT
)

    # Run tests in container
    local output
    local docker_exit_code

    output=$(docker run --rm \
        -v "${VPS_AUDIT_SCRIPT}:/test/vps-audit.sh:ro" \
        --entrypoint /bin/sh \
        "$image" \
        -c "
echo '=== Setup Phase ==='
echo 'Installing required packages...'
if ${setup_cmd}; then
    echo 'Setup: SUCCESS'
else
    echo 'Setup: FAILED (exit code: '\$?')'
    echo 'Continuing anyway to see what happens...'
fi
echo ''
echo '=== Test Phase ==='
cat > /tmp/test.sh << 'EOF'
${test_script}
EOF
bash /tmp/test.sh
" 2>&1) || docker_exit_code=$?

    docker_exit_code=${docker_exit_code:-0}

    # Save output to log file
    {
        echo "Test Results for ${display_name} (${image})"
        echo "Timestamp: $(date)"
        echo "================================================"
        echo ""
        echo "$output"
        echo ""
        echo "Exit code: ${docker_exit_code}"
    } > "$result_file"

    # Parse results
    if [[ $docker_exit_code -eq 0 ]] || echo "$output" | grep -q "All tests completed successfully"; then
        log_success "${display_name} - All tests passed"
        TEST_RESULTS[$image]="PASSED"
        ((PASSED_TESTS++))
        return 0
    else
        log_error "${display_name} - Tests failed (see ${result_file})"
        TEST_RESULTS[$image]="FAILED"
        ((FAILED_TESTS++))
        # Show last few lines of output
        echo "Last output:"
        echo "$output" | tail -20
        return 1
    fi
}

# Run static analysis tests (shellcheck)
run_static_analysis() {
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "${BOLD}Static Analysis Tests${NC}"
    echo "═══════════════════════════════════════════════════════════════"

    ((TOTAL_TESTS++))

    # Bash syntax check
    log_info "Running bash -n syntax check..."
    if bash -n "$VPS_AUDIT_SCRIPT"; then
        log_success "Bash syntax check passed"
    else
        log_error "Bash syntax check failed"
        ((FAILED_TESTS++))
        return 1
    fi

    # Shellcheck
    if command -v shellcheck &>/dev/null; then
        log_info "Running shellcheck..."
        local shellcheck_output
        shellcheck_output=$(shellcheck -x -S warning "$VPS_AUDIT_SCRIPT" 2>&1) || true

        if [[ -z "$shellcheck_output" ]]; then
            log_success "Shellcheck passed with no warnings"
            ((PASSED_TESTS++))
        else
            local error_count
            error_count=$(echo "$shellcheck_output" | grep -c "^In " || echo 0)
            if [[ $error_count -gt 0 ]]; then
                log_error "Shellcheck found $error_count issues:"
                echo "$shellcheck_output"
                ((FAILED_TESTS++))
                return 1
            else
                log_success "Shellcheck passed"
                ((PASSED_TESTS++))
            fi
        fi
    else
        log_warn "Shellcheck not installed - skipping"
        ((SKIPPED_TESTS++))
    fi

    return 0
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    echo "═══════════════════════════════════════════════════════════════"
    echo "${BOLD}VPS Audit Test Matrix${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Script: ${VPS_AUDIT_SCRIPT}"
    echo "Date: $(date)"
    echo ""

    # Verify script exists
    if [[ ! -f "$VPS_AUDIT_SCRIPT" ]]; then
        log_error "vps-audit.sh not found at: $VPS_AUDIT_SCRIPT"
        exit 1
    fi

    # Check Docker
    check_docker

    # Setup results directory
    setup_results_dir

    # Run static analysis first
    run_static_analysis

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "${BOLD}Distribution Tests${NC}"
    echo "═══════════════════════════════════════════════════════════════"

    # Parse command line arguments
    local selected_distros=()
    if [[ $# -gt 0 ]]; then
        # Filter distros based on arguments
        for arg in "$@"; do
            for image in "${!DISTROS[@]}"; do
                if [[ "$image" == *"$arg"* ]] || [[ "${DISTROS[$image]}" == *"$arg"* ]]; then
                    selected_distros+=("$image")
                fi
            done
        done

        if [[ ${#selected_distros[@]} -eq 0 ]]; then
            log_error "No matching distributions found for: $*"
            log_info "Available distributions:"
            for image in "${!DISTROS[@]}"; do
                echo "  - ${DISTROS[$image]} ($image)"
            done
            exit 1
        fi
    else
        # Test all distros
        selected_distros=("${!DISTROS[@]}")
    fi

    # Run tests on each distribution
    for image in "${selected_distros[@]}"; do
        test_distro "$image" "${DISTROS[$image]}" || true
    done

    # Print summary
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "${BOLD}Test Summary${NC}"
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    echo "Total tests:   $TOTAL_TESTS"
    echo -e "Passed:        ${GREEN}${PASSED_TESTS}${NC}"
    echo -e "Failed:        ${RED}${FAILED_TESTS}${NC}"
    echo -e "Skipped:       ${YELLOW}${SKIPPED_TESTS}${NC}"
    echo ""

    # Print detailed results
    echo "Results by distribution:"
    for image in "${!TEST_RESULTS[@]}"; do
        local result="${TEST_RESULTS[$image]}"
        local display_name="${DISTROS[$image]:-$image}"
        case "$result" in
            PASSED)  echo -e "  ${GREEN}✓${NC} ${display_name}" ;;
            FAILED)  echo -e "  ${RED}✗${NC} ${display_name}" ;;
            SKIPPED) echo -e "  ${YELLOW}○${NC} ${display_name}" ;;
        esac
    done

    echo ""
    echo "Detailed logs saved to: ${TEST_RESULTS_DIR}"

    # Exit with appropriate code
    if [[ $FAILED_TESTS -gt 0 ]]; then
        exit 1
    elif [[ $PASSED_TESTS -eq 0 ]]; then
        exit 2
    else
        exit 0
    fi
}

# Show usage
usage() {
    cat << EOF
VPS Audit Test Matrix

Usage: $0 [OPTIONS] [DISTRO_FILTER...]

Options:
    -h, --help      Show this help message
    -l, --list      List available distributions

Arguments:
    DISTRO_FILTER   Optional filter(s) to test specific distributions
                    (e.g., "ubuntu" "alpine" "rocky")

Examples:
    $0                      # Test all distributions
    $0 ubuntu debian        # Test only Ubuntu and Debian
    $0 alpine               # Test only Alpine variants
    $0 -l                   # List available distributions

Available Distributions:
EOF
    for image in "${!DISTROS[@]}"; do
        echo "    ${DISTROS[$image]} ($image)"
    done | sort
}

# Parse arguments
case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
    -l|--list)
        echo "Available distributions:"
        for image in "${!DISTROS[@]}"; do
            echo "  ${DISTROS[$image]} ($image)"
        done | sort
        exit 0
        ;;
esac

main "$@"
