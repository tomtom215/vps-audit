#!/usr/bin/env bash
#
# VPS Security Audit Tool
# Version: 2.0.0
# https://github.com/vernu/vps-audit
#
# A comprehensive security and performance auditing tool for Linux VPS systems.
# Supports: Debian, Ubuntu, RHEL, CentOS, Fedora, Rocky, Alma, Arch, Alpine, openSUSE
#

# =============================================================================
# PHASE 1: CORE INFRASTRUCTURE & SAFETY
# =============================================================================

# Exit on error, undefined variables, and pipeline failures (Issue #1)
set -o pipefail

# Script version for tracking (Issue #33)
readonly VERSION="2.0.0"

# Global state
REPORT_FILE=""
CLEANUP_ON_ERROR=true
JSON_OUTPUT=""
declare -i PASS_COUNT=0
declare -i WARN_COUNT=0
declare -i FAIL_COUNT=0
declare -i CRITICAL_FAIL_COUNT=0
declare -a RECOMMENDATIONS=()

# =============================================================================
# PHASE 2: CONFIGURATION & THRESHOLDS
# =============================================================================

# Default configuration (Issue #34)
declare -A CONFIG=(
    [output_dir]="."
    [output_format]="text"
    [verbosity]="normal"
    [skip_network]="false"
    [skip_suid_scan]="false"
    [checks]="all"
    [quiet]="false"
    [dry_run]="false"
)

# Configurable thresholds (Issue #37)
declare -A THRESHOLDS=(
    # Resource thresholds
    [disk_warn]=50
    [disk_fail]=80
    [mem_warn]=50
    [mem_fail]=80
    [cpu_warn]=50
    [cpu_fail]=80
    # Security thresholds
    [failed_logins_warn]=10
    [failed_logins_fail]=50
    [services_warn]=20
    [services_fail]=40
    [ports_warn]=10
    [ports_fail]=20
    [public_ports_warn]=3
    [public_ports_fail]=5
)

# OS Information (Issue #64)
declare -A OS_INFO=(
    [id]=""
    [id_like]=""
    [version]=""
    [name]=""
    [family]=""
    [pkg_manager]=""
    [service_manager]=""
    [auth_log]=""
)

# =============================================================================
# TERMINAL & COLOR HANDLING (Issue #22)
# =============================================================================

init_colors() {
    if [[ -t 1 ]] && [[ "${NO_COLOR:-}" != "1" ]] && [[ "${CONFIG[quiet]}" != "true" ]]; then
        readonly GREEN='\033[0;32m'
        readonly RED='\033[0;31m'
        readonly YELLOW='\033[1;33m'
        readonly GRAY='\033[0;90m'
        readonly BLUE='\033[0;34m'
        readonly BOLD='\033[1m'
        readonly NC='\033[0m'
    else
        readonly GREEN=''
        readonly RED=''
        readonly YELLOW=''
        readonly GRAY=''
        readonly BLUE=''
        readonly BOLD=''
        readonly NC=''
    fi
}

# =============================================================================
# LOGGING SYSTEM (Issue #39)
# =============================================================================

log_debug() {
    if [[ "${CONFIG[verbosity]}" == "verbose" ]]; then
        echo -e "${GRAY}[DEBUG] $*${NC}" >&2
    fi
}

log_verbose() {
    if [[ "${CONFIG[verbosity]}" != "quiet" ]] && [[ "${CONFIG[quiet]}" != "true" ]]; then
        echo -e "${GRAY}[INFO] $*${NC}"
    fi
}

log_error() {
    echo -e "${RED}[ERROR] $*${NC}" >&2
    if [[ -n "$REPORT_FILE" ]] && [[ -f "$REPORT_FILE" ]]; then
        echo "[ERROR] $*" >> "$REPORT_FILE"
    fi
}

log_warning() {
    if [[ "${CONFIG[quiet]}" != "true" ]]; then
        echo -e "${YELLOW}[WARNING] $*${NC}" >&2
    fi
}

# Output function respecting quiet mode (Issue #75)
output() {
    if [[ "${CONFIG[quiet]}" != "true" ]]; then
        echo -e "$@"
    fi
}

# Progress indicator for long operations (Issue #41)
show_progress() {
    local message="$1"
    if [[ "${CONFIG[quiet]}" != "true" ]] && [[ -t 1 ]]; then
        echo -ne "${GRAY}${message}...${NC}\r"
    fi
}

clear_progress() {
    if [[ "${CONFIG[quiet]}" != "true" ]] && [[ -t 1 ]]; then
        echo -ne "\033[2K\r"
    fi
}

# =============================================================================
# CLEANUP & TRAP HANDLERS (Issue #21)
# =============================================================================

cleanup() {
    local exit_code=$?

    clear_progress

    if [[ $exit_code -ne 0 ]] && [[ "$CLEANUP_ON_ERROR" == "true" ]]; then
        if [[ -n "$REPORT_FILE" ]] && [[ -f "$REPORT_FILE" ]]; then
            rm -f "$REPORT_FILE" 2>/dev/null
            echo "Cleaned up partial report file due to error" >&2
        fi
    fi

    exit $exit_code
}

trap cleanup EXIT INT TERM

# =============================================================================
# INPUT VALIDATION (Issue #44, #6, #13)
# =============================================================================

is_numeric() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]]
}

validate_percentage() {
    local value="$1"
    is_numeric "$value" && [[ $value -ge 0 ]] && [[ $value -le 100 ]]
}

# Safe command execution with error handling (Issue #45)
safe_exec() {
    local cmd="$1"
    local default="${2:-}"
    local result

    if result=$(eval "$cmd" 2>/dev/null); then
        echo "$result"
    else
        log_debug "Command failed: $cmd"
        echo "$default"
    fi
}

# =============================================================================
# ROOT CHECK (Issue #9)
# =============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: This script must be run as root or with sudo" >&2
        echo "Usage: sudo $0 [options]" >&2
        exit 1
    fi
}

# =============================================================================
# SECURE FILE CREATION (Issues #2, #3)
# =============================================================================

create_report_file() {
    local report_dir="${CONFIG[output_dir]}"

    # Set restrictive umask
    umask 077

    # Verify directory exists and is writable
    if [[ ! -d "$report_dir" ]]; then
        log_error "Report directory does not exist: $report_dir"
        exit 1
    fi

    if [[ ! -w "$report_dir" ]]; then
        log_error "Report directory is not writable: $report_dir"
        exit 1
    fi

    # Create file with secure permissions using mktemp
    REPORT_FILE=$(mktemp "${report_dir}/vps-audit-report-XXXXXX.txt") || {
        log_error "Failed to create report file"
        exit 1
    }

    # Double-check permissions
    chmod 600 "$REPORT_FILE"

    log_debug "Report file created: $REPORT_FILE"
}

# =============================================================================
# OS DETECTION (Issues #64, #65, #66, #67, #68)
# =============================================================================

detect_os() {
    # Read os-release - parse instead of source to avoid variable conflicts
    if [[ -f /etc/os-release ]]; then
        OS_INFO[id]=$(grep "^ID=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown")
        OS_INFO[id_like]=$(grep "^ID_LIKE=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "")
        OS_INFO[version]=$(grep "^VERSION_ID=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "")
        OS_INFO[name]=$(grep "^PRETTY_NAME=" /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "Unknown OS")
    elif [[ -f /etc/redhat-release ]]; then
        OS_INFO[id]="rhel"
        OS_INFO[name]=$(cat /etc/redhat-release)
    else
        OS_INFO[id]="unknown"
        OS_INFO[name]="Unknown OS"
    fi

    # Determine OS family
    case "${OS_INFO[id]}" in
        ubuntu|debian|linuxmint|pop|elementary|kali|raspbian|zorin)
            OS_INFO[family]="debian"
            OS_INFO[pkg_manager]="apt"
            OS_INFO[auth_log]="/var/log/auth.log"
            ;;
        rhel|centos|fedora|rocky|alma|ol|scientific|amzn)
            OS_INFO[family]="rhel"
            if command -v dnf &>/dev/null; then
                OS_INFO[pkg_manager]="dnf"
            else
                OS_INFO[pkg_manager]="yum"
            fi
            OS_INFO[auth_log]="/var/log/secure"
            ;;
        arch|manjaro|endeavouros|artix)
            OS_INFO[family]="arch"
            OS_INFO[pkg_manager]="pacman"
            OS_INFO[auth_log]="/var/log/auth.log"
            ;;
        opensuse*|sles|suse)
            OS_INFO[family]="suse"
            OS_INFO[pkg_manager]="zypper"
            OS_INFO[auth_log]="/var/log/messages"
            ;;
        alpine)
            OS_INFO[family]="alpine"
            OS_INFO[pkg_manager]="apk"
            OS_INFO[auth_log]="/var/log/messages"
            ;;
        *)
            # Try to detect from ID_LIKE
            if [[ "${OS_INFO[id_like]}" =~ debian|ubuntu ]]; then
                OS_INFO[family]="debian"
                OS_INFO[pkg_manager]="apt"
                OS_INFO[auth_log]="/var/log/auth.log"
            elif [[ "${OS_INFO[id_like]}" =~ rhel|fedora|centos ]]; then
                OS_INFO[family]="rhel"
                OS_INFO[pkg_manager]="yum"
                OS_INFO[auth_log]="/var/log/secure"
            else
                OS_INFO[family]="unknown"
                OS_INFO[pkg_manager]="unknown"
                OS_INFO[auth_log]=""
            fi
            ;;
    esac

    # Detect service manager (Issue #66)
    if command -v systemctl &>/dev/null && systemctl --version &>/dev/null 2>&1; then
        OS_INFO[service_manager]="systemd"
    elif command -v rc-service &>/dev/null; then
        OS_INFO[service_manager]="openrc"
    elif command -v service &>/dev/null; then
        OS_INFO[service_manager]="sysv"
    elif [[ -d /etc/runit/runsvdir ]]; then
        OS_INFO[service_manager]="runit"
    else
        OS_INFO[service_manager]="unknown"
    fi

    log_debug "Detected OS: ${OS_INFO[name]} (${OS_INFO[family]})"
    log_debug "Package manager: ${OS_INFO[pkg_manager]}"
    log_debug "Service manager: ${OS_INFO[service_manager]}"
    log_debug "Auth log: ${OS_INFO[auth_log]}"
}

# =============================================================================
# PACKAGE MANAGER ABSTRACTION (Issues #14, #15)
# =============================================================================

pkg_installed() {
    local package="$1"

    case "${OS_INFO[pkg_manager]}" in
        apt)
            dpkg -l "$package" 2>/dev/null | grep -q "^ii"
            ;;
        dnf|yum)
            rpm -q "$package" &>/dev/null
            ;;
        pacman)
            pacman -Qi "$package" &>/dev/null
            ;;
        zypper)
            rpm -q "$package" &>/dev/null
            ;;
        apk)
            apk info -e "$package" &>/dev/null
            ;;
        *)
            log_debug "Unknown package manager, cannot check package: $package"
            return 1
            ;;
    esac
}

get_update_count() {
    local count=0

    case "${OS_INFO[pkg_manager]}" in
        apt)
            count=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst " || echo 0)
            ;;
        dnf)
            count=$(dnf check-update -q 2>/dev/null | grep -c "^[a-zA-Z]" || echo 0)
            ;;
        yum)
            count=$(yum check-update -q 2>/dev/null | grep -c "^[a-zA-Z]" || echo 0)
            ;;
        pacman)
            count=$(pacman -Qu 2>/dev/null | wc -l || echo 0)
            ;;
        zypper)
            count=$(zypper -q lu 2>/dev/null | grep -c "^v" || echo 0)
            ;;
        apk)
            count=$(apk version -l '<' 2>/dev/null | wc -l || echo 0)
            ;;
        *)
            log_warning "Cannot check updates for unknown package manager"
            return 1
            ;;
    esac

    echo "$count"
}

get_security_update_count() {
    local count=0

    case "${OS_INFO[pkg_manager]}" in
        apt)
            count=$(apt-get -s upgrade 2>/dev/null | grep -i security | grep -c "^Inst " || echo 0)
            ;;
        dnf)
            count=$(dnf updateinfo list security --available 2>/dev/null | grep -c "^" || echo 0)
            ;;
        yum)
            count=$(yum updateinfo list security 2>/dev/null | grep -c "^" || echo 0)
            ;;
        *)
            # Fall back to total updates for other package managers
            count=$(get_update_count)
            ;;
    esac

    echo "$count"
}

# =============================================================================
# SERVICE MANAGER ABSTRACTION (Issue #66)
# =============================================================================

service_is_active() {
    local service="$1"

    case "${OS_INFO[service_manager]}" in
        systemd)
            systemctl is-active "$service" &>/dev/null
            ;;
        openrc)
            rc-service "$service" status &>/dev/null
            ;;
        sysv)
            service "$service" status &>/dev/null
            ;;
        runit)
            sv status "$service" 2>/dev/null | grep -q "^run:"
            ;;
        *)
            log_debug "Unknown service manager, cannot check service: $service"
            return 1
            ;;
    esac
}

get_running_services_count() {
    local count=0

    case "${OS_INFO[service_manager]}" in
        systemd)
            count=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | wc -l)
            ;;
        openrc)
            count=$(rc-status -s 2>/dev/null | grep -c "started" || echo 0)
            ;;
        sysv)
            count=$(service --status-all 2>/dev/null | grep -c " + " || echo 0)
            ;;
        runit)
            count=$(ls /var/service 2>/dev/null | wc -l || echo 0)
            ;;
        *)
            log_warning "Cannot count services for unknown service manager"
            return 1
            ;;
    esac

    echo "$count"
}

# =============================================================================
# PORTABLE COMMAND WRAPPERS (Issue #67)
# =============================================================================

get_uptime() {
    if uptime -p &>/dev/null 2>&1; then
        uptime -p
    else
        # Fallback for systems without -p flag
        local uptime_seconds
        uptime_seconds=$(cut -d. -f1 /proc/uptime 2>/dev/null)
        if [[ -n "$uptime_seconds" ]]; then
            local days=$((uptime_seconds / 86400))
            local hours=$(((uptime_seconds % 86400) / 3600))
            local minutes=$(((uptime_seconds % 3600) / 60))
            echo "up ${days} days, ${hours} hours, ${minutes} minutes"
        else
            uptime | sed 's/.*up/up/' | sed 's/,.*load.*//'
        fi
    fi
}

get_uptime_since() {
    if uptime -s &>/dev/null 2>&1; then
        uptime -s
    else
        local uptime_seconds
        uptime_seconds=$(cut -d. -f1 /proc/uptime 2>/dev/null)
        if [[ -n "$uptime_seconds" ]]; then
            date -d "@$(($(date +%s) - uptime_seconds))" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "unknown"
        else
            echo "unknown"
        fi
    fi
}

get_memory_stats() {
    local stat="$1"  # total, used, available, percent

    if command -v free &>/dev/null; then
        case "$stat" in
            total)
                free -b 2>/dev/null | awk '/^Mem:/ {print $2}'
                ;;
            used)
                free -b 2>/dev/null | awk '/^Mem:/ {print $3}'
                ;;
            available)
                # Try column 7 first (available), fall back to free + buffers/cache
                free -b 2>/dev/null | awk '/^Mem:/ {if (NF >= 7) print $7; else print $4 + $6}'
                ;;
            percent)
                free 2>/dev/null | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}'
                ;;
            total_human)
                free -h 2>/dev/null | awk '/^Mem:/ {print $2}'
                ;;
            used_human)
                free -h 2>/dev/null | awk '/^Mem:/ {print $3}'
                ;;
            available_human)
                free -h 2>/dev/null | awk '/^Mem:/ {if (NF >= 7) print $7; else print $4}'
                ;;
        esac
    else
        # Fallback to /proc/meminfo
        case "$stat" in
            total)
                awk '/MemTotal/ {print $2 * 1024}' /proc/meminfo
                ;;
            available)
                awk '/MemAvailable/ {print $2 * 1024}' /proc/meminfo 2>/dev/null || \
                awk '/MemFree/ {print $2 * 1024}' /proc/meminfo
                ;;
            percent)
                awk '/MemTotal/ {total=$2} /MemAvailable/ {avail=$2} END {printf "%.0f", (total-avail)/total * 100}' /proc/meminfo
                ;;
        esac
    fi
}

# =============================================================================
# OUTPUT FUNCTIONS
# =============================================================================

print_header() {
    local header="$1"
    output "\n${BLUE}${BOLD}$header${NC}"
    echo -e "\n$header" >> "$REPORT_FILE"
    echo "================================" >> "$REPORT_FILE"
}

print_info() {
    local label="${1:-}"
    local value="${2:-}"

    if [[ -z "$label" ]]; then
        log_error "print_info called without label"
        return 1
    fi

    # Value can be empty, but show placeholder
    if [[ -z "$value" ]]; then
        value="(not available)"
    fi

    output "${BOLD}$label:${NC} $value"
    echo "$label: $value" >> "$REPORT_FILE"
}

# Enhanced check_security with recommendations (Issues #43, #70, #71, #42)
check_security() {
    local test_name="${1:-}"
    local status="${2:-}"
    local message="${3:-}"
    local recommendation="${4:-}"
    local is_critical="${5:-false}"

    # Validate required parameters (Issue #44)
    if [[ -z "$test_name" ]] || [[ -z "$status" ]] || [[ -z "$message" ]]; then
        log_error "check_security called with missing parameters"
        return 1
    fi

    # Validate status value (Issue #43)
    case "$status" in
        PASS|WARN|FAIL) ;;
        *)
            log_error "Invalid status '$status' for test '$test_name'"
            return 1
            ;;
    esac

    # Record result
    case $status in
        "PASS")
            ((PASS_COUNT++)) || true
            output "${GREEN}[PASS]${NC} $test_name ${GRAY}- $message${NC}"
            ;;
        "WARN")
            ((WARN_COUNT++)) || true
            output "${YELLOW}[WARN]${NC} $test_name ${GRAY}- $message${NC}"
            ;;
        "FAIL")
            ((FAIL_COUNT++)) || true
            if [[ "$is_critical" == "true" ]]; then
                ((CRITICAL_FAIL_COUNT++)) || true
            fi
            output "${RED}[FAIL]${NC} $test_name ${GRAY}- $message${NC}"
            ;;
    esac

    echo "[$status] $test_name - $message" >> "$REPORT_FILE"

    # Store recommendation for failed/warning checks (Issue #70)
    if [[ "$status" != "PASS" ]] && [[ -n "$recommendation" ]]; then
        RECOMMENDATIONS+=("[$test_name] $recommendation")
        echo "  Recommendation: $recommendation" >> "$REPORT_FILE"
    fi

    echo "" >> "$REPORT_FILE"

    # Add to JSON output if enabled
    if [[ "${CONFIG[output_format]}" == "json" ]] || [[ "${CONFIG[output_format]}" == "both" ]]; then
        add_json_result "$test_name" "$status" "$message"
    fi
}

# =============================================================================
# JSON OUTPUT (Issue #72)
# =============================================================================

init_json() {
    JSON_OUTPUT='{"version":"'"$VERSION"'","timestamp":"'"$(date -Iseconds 2>/dev/null || date)"'","hostname":"'"$(hostname)"'","os":"'"${OS_INFO[name]}"'","checks":['
}

add_json_result() {
    local test_name="$1"
    local status="$2"
    local message="$3"

    # Escape JSON strings
    test_name=$(echo "$test_name" | sed 's/"/\\"/g; s/\\/\\\\/g')
    message=$(echo "$message" | sed 's/"/\\"/g; s/\\/\\\\/g')

    local json_entry='{"name":"'"$test_name"'","status":"'"$status"'","message":"'"$message"'"}'

    if [[ "$JSON_OUTPUT" == *'"checks":['* ]] && [[ "$JSON_OUTPUT" != *'"checks":[]'* ]] && [[ "${JSON_OUTPUT: -1}" != "[" ]]; then
        JSON_OUTPUT+=",$json_entry"
    else
        JSON_OUTPUT+="$json_entry"
    fi
}

finalize_json() {
    JSON_OUTPUT+='],"summary":{"pass":'"$PASS_COUNT"',"warn":'"$WARN_COUNT"',"fail":'"$FAIL_COUNT"',"critical_fail":'"$CRITICAL_FAIL_COUNT"'}}'

    if [[ "${CONFIG[output_format]}" == "json" ]] || [[ "${CONFIG[output_format]}" == "both" ]]; then
        local json_file="${REPORT_FILE%.txt}.json"
        echo "$JSON_OUTPUT" > "$json_file"
        chmod 600 "$json_file"
        output "\nJSON report saved to: $json_file"
    fi
}

# =============================================================================
# COMMAND LINE ARGUMENT PARSING (Issue #34)
# =============================================================================

usage() {
    cat << EOF
VPS Security Audit Tool v${VERSION}

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    -v, --version           Show version information
    -q, --quiet             Suppress console output (for cron jobs)
    -o, --output DIR        Output directory for report (default: current)
    -f, --format FORMAT     Output format: text, json, both (default: text)
    -V, --verbose           Enable verbose/debug output
    --no-network            Skip checks requiring network access
    --no-suid               Skip SUID file scan (can be slow)
    --checks LIST           Comma-separated list of checks to run
    --dry-run               Show what checks would run without executing

Threshold Options:
    --disk-warn PCT         Disk usage warning threshold (default: 50)
    --disk-fail PCT         Disk usage failure threshold (default: 80)
    --mem-warn PCT          Memory usage warning threshold (default: 50)
    --mem-fail PCT          Memory usage failure threshold (default: 80)
    --login-warn NUM        Failed login warning threshold (default: 10)
    --login-fail NUM        Failed login failure threshold (default: 50)

Examples:
    sudo $0                         # Run all checks
    sudo $0 -q -f json              # Quiet mode with JSON output
    sudo $0 --no-suid --no-network  # Skip slow/network checks

Report bugs to: https://github.com/vernu/vps-audit/issues
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                echo "VPS Security Audit Tool v${VERSION}"
                exit 0
                ;;
            -q|--quiet)
                CONFIG[quiet]="true"
                ;;
            -o|--output)
                if [[ -n "${2:-}" ]]; then
                    CONFIG[output_dir]="$2"
                    shift
                else
                    log_error "Option $1 requires an argument"
                    exit 1
                fi
                ;;
            -f|--format)
                if [[ -n "${2:-}" ]]; then
                    case "$2" in
                        text|json|both)
                            CONFIG[output_format]="$2"
                            ;;
                        *)
                            log_error "Invalid format: $2 (must be text, json, or both)"
                            exit 1
                            ;;
                    esac
                    shift
                else
                    log_error "Option $1 requires an argument"
                    exit 1
                fi
                ;;
            -V|--verbose)
                CONFIG[verbosity]="verbose"
                ;;
            --no-network)
                CONFIG[skip_network]="true"
                ;;
            --no-suid)
                CONFIG[skip_suid_scan]="true"
                ;;
            --checks)
                if [[ -n "${2:-}" ]]; then
                    CONFIG[checks]="$2"
                    shift
                else
                    log_error "Option $1 requires an argument"
                    exit 1
                fi
                ;;
            --dry-run)
                CONFIG[dry_run]="true"
                ;;
            --disk-warn)
                if [[ -n "${2:-}" ]] && is_numeric "$2"; then
                    THRESHOLDS[disk_warn]="$2"
                    shift
                else
                    log_error "Option $1 requires a numeric argument"
                    exit 1
                fi
                ;;
            --disk-fail)
                if [[ -n "${2:-}" ]] && is_numeric "$2"; then
                    THRESHOLDS[disk_fail]="$2"
                    shift
                else
                    log_error "Option $1 requires a numeric argument"
                    exit 1
                fi
                ;;
            --mem-warn)
                if [[ -n "${2:-}" ]] && is_numeric "$2"; then
                    THRESHOLDS[mem_warn]="$2"
                    shift
                else
                    log_error "Option $1 requires a numeric argument"
                    exit 1
                fi
                ;;
            --mem-fail)
                if [[ -n "${2:-}" ]] && is_numeric "$2"; then
                    THRESHOLDS[mem_fail]="$2"
                    shift
                else
                    log_error "Option $1 requires a numeric argument"
                    exit 1
                fi
                ;;
            --login-warn)
                if [[ -n "${2:-}" ]] && is_numeric "$2"; then
                    THRESHOLDS[failed_logins_warn]="$2"
                    shift
                else
                    log_error "Option $1 requires a numeric argument"
                    exit 1
                fi
                ;;
            --login-fail)
                if [[ -n "${2:-}" ]] && is_numeric "$2"; then
                    THRESHOLDS[failed_logins_fail]="$2"
                    shift
                else
                    log_error "Option $1 requires a numeric argument"
                    exit 1
                fi
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                log_error "Unexpected argument: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done
}

# Load configuration file if exists
load_config() {
    local config_files=(
        "/etc/vps-audit.conf"
        "$HOME/.vps-audit.conf"
        "./.vps-audit.conf"
    )

    for config_file in "${config_files[@]}"; do
        if [[ -f "$config_file" ]] && [[ -r "$config_file" ]]; then
            log_debug "Loading config from: $config_file"
            # shellcheck source=/dev/null
            source "$config_file"
        fi
    done
}

# Check if a specific check should run
should_run_check() {
    local check_name="$1"

    if [[ "${CONFIG[dry_run]}" == "true" ]]; then
        output "[DRY-RUN] Would run check: $check_name"
        return 1
    fi

    if [[ "${CONFIG[checks]}" != "all" ]]; then
        if [[ ! ",${CONFIG[checks]}," =~ ,$check_name, ]]; then
            log_debug "Skipping check (not in list): $check_name"
            return 1
        fi
    fi

    return 0
}

# =============================================================================
# SSH CONFIGURATION CHECKS (Issues #5, #23, #24)
# =============================================================================

get_ssh_config() {
    local setting="$1"
    local default="$2"
    local value=""
    local config_files=()

    # Check for Include directives in main config
    local include_pattern
    include_pattern=$(grep -h "^Include" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)

    if [[ -n "$include_pattern" ]]; then
        local dir
        dir=$(dirname "$include_pattern" 2>/dev/null)

        if [[ -d "$dir" ]]; then
            # Expand glob pattern safely
            while IFS= read -r -d '' file; do
                [[ -f "$file" ]] && config_files+=("$file")
            done < <(find "$dir" -maxdepth 1 -type f -name "$(basename "$include_pattern")" -print0 2>/dev/null | sort -z)
        fi
    fi

    # Add main config file
    config_files+=("/etc/ssh/sshd_config")

    # Search through files for the setting (first match wins)
    for config in "${config_files[@]}"; do
        if [[ -f "$config" ]] && [[ -r "$config" ]]; then
            value=$(grep -i "^[[:space:]]*${setting}[[:space:]]" "$config" 2>/dev/null | head -1 | awk '{print $2}')
            if [[ -n "$value" ]]; then
                log_debug "Found $setting=$value in $config"
                echo "$value"
                return 0
            fi
        fi
    done

    # Return default if not found
    echo "$default"
}

check_ssh_root_login() {
    should_run_check "ssh" || return 0

    # Default depends on OpenSSH version (7.0+ defaults to prohibit-password)
    local default_value="prohibit-password"

    local ssh_root
    ssh_root=$(get_ssh_config "PermitRootLogin" "$default_value")

    case "$ssh_root" in
        no)
            check_security "SSH Root Login" "PASS" "Root login is disabled" ""
            ;;
        prohibit-password|without-password)
            check_security "SSH Root Login" "WARN" "Root login allowed with key only (no password)" \
                "Consider setting PermitRootLogin to 'no' and using a regular user with sudo"
            ;;
        forced-commands-only)
            check_security "SSH Root Login" "WARN" "Root login allowed for forced commands only" \
                "Review forced commands for security implications"
            ;;
        yes)
            check_security "SSH Root Login" "FAIL" "Root login is enabled with password" \
                "Set PermitRootLogin to 'no' in /etc/ssh/sshd_config" "true"
            ;;
        *)
            check_security "SSH Root Login" "WARN" "Unknown PermitRootLogin value: $ssh_root" \
                "Verify SSH configuration manually"
            ;;
    esac
}

check_ssh_password_auth() {
    should_run_check "ssh" || return 0

    local ssh_password
    ssh_password=$(get_ssh_config "PasswordAuthentication" "yes")

    if [[ "$ssh_password" == "no" ]]; then
        check_security "SSH Password Auth" "PASS" "Password authentication disabled, key-based only" ""
    else
        check_security "SSH Password Auth" "WARN" "Password authentication enabled" \
            "Consider disabling password auth and using SSH keys only"
    fi
}

check_ssh_port() {
    should_run_check "ssh" || return 0

    local ssh_port
    ssh_port=$(get_ssh_config "Port" "22")

    # Validate it's numeric
    if ! is_numeric "$ssh_port"; then
        check_security "SSH Port" "WARN" "Invalid SSH port configuration: $ssh_port" \
            "Review SSH configuration"
        return
    fi

    local unprivileged_start
    unprivileged_start=$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || echo 1024)

    if ! is_numeric "$unprivileged_start"; then
        unprivileged_start=1024
    fi

    if [[ "$ssh_port" == "22" ]]; then
        check_security "SSH Port" "PASS" "Using standard port 22" ""
    elif [[ $ssh_port -ge $unprivileged_start ]]; then
        check_security "SSH Port" "WARN" "Using unprivileged port $ssh_port" \
            "Consider using a port below $unprivileged_start"
    elif [[ $ssh_port -lt 1 ]] || [[ $ssh_port -gt 65535 ]]; then
        check_security "SSH Port" "FAIL" "Invalid SSH port: $ssh_port" \
            "Configure a valid port (1-65535)"
    else
        check_security "SSH Port" "PASS" "Using non-standard privileged port $ssh_port" ""
    fi
}

# =============================================================================
# FIREWALL CHECKS (Issue #16)
# =============================================================================

check_firewall_status() {
    should_run_check "firewall" || return 0

    local firewall_found=false
    local firewall_active=false
    local firewall_name=""

    # Check UFW (Debian/Ubuntu)
    if command -v ufw &>/dev/null; then
        firewall_found=true
        firewall_name="UFW"
        if ufw status 2>/dev/null | grep -qw "active"; then
            firewall_active=true
        fi
    fi

    # Check firewalld (RHEL/CentOS/Fedora)
    if [[ "$firewall_active" == "false" ]] && command -v firewall-cmd &>/dev/null; then
        firewall_found=true
        firewall_name="firewalld"
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            firewall_active=true
        fi
    fi

    # Check nftables
    if [[ "$firewall_active" == "false" ]] && command -v nft &>/dev/null; then
        firewall_found=true
        firewall_name="nftables"
        local rule_count
        rule_count=$(nft list ruleset 2>/dev/null | grep -c "chain" || echo 0)
        if [[ $rule_count -gt 0 ]]; then
            firewall_active=true
        fi
    fi

    # Check iptables (legacy) - Fixed Issue #16
    if [[ "$firewall_active" == "false" ]] && command -v iptables &>/dev/null; then
        firewall_found=true
        firewall_name="iptables"

        # Count actual rules in INPUT chain (excluding header lines)
        local input_rules
        input_rules=$(iptables -L INPUT -n --line-numbers 2>/dev/null | tail -n +3 | wc -l || echo 0)

        # Check if default policy is DROP/REJECT
        local input_policy
        input_policy=$(iptables -L INPUT -n 2>/dev/null | head -1 | grep -oP '\(policy \K[A-Z]+' || echo "ACCEPT")

        if [[ $input_rules -gt 0 ]] || [[ "$input_policy" == "DROP" ]] || [[ "$input_policy" == "REJECT" ]]; then
            firewall_active=true
        fi
    fi

    # Report results
    if [[ "$firewall_found" == "false" ]]; then
        check_security "Firewall Status" "FAIL" "No firewall tool found" \
            "Install and configure ufw, firewalld, or iptables" "true"
    elif [[ "$firewall_active" == "true" ]]; then
        check_security "Firewall Status ($firewall_name)" "PASS" "$firewall_name is active and protecting the system" ""
    else
        check_security "Firewall Status ($firewall_name)" "FAIL" "$firewall_name installed but not properly configured" \
            "Enable and configure $firewall_name" "true"
    fi
}

# =============================================================================
# INTRUSION PREVENTION CHECK
# =============================================================================

check_intrusion_prevention() {
    should_run_check "ips" || return 0

    local ips_installed=false
    local ips_active=false
    local ips_name=""

    # Check fail2ban
    if pkg_installed fail2ban; then
        ips_installed=true
        ips_name="Fail2ban"
        if service_is_active fail2ban; then
            ips_active=true
        fi
    fi

    # Check CrowdSec
    if pkg_installed crowdsec; then
        ips_installed=true
        ips_name="${ips_name:+$ips_name/}CrowdSec"
        if service_is_active crowdsec; then
            ips_active=true
        fi
    fi

    # Check Docker containers for fail2ban/crowdsec
    if command -v docker &>/dev/null && service_is_active docker 2>/dev/null; then
        if docker ps --format '{{.Image}}' 2>/dev/null | grep -qi "fail2ban"; then
            ips_installed=true
            ips_active=true
            ips_name="${ips_name:+$ips_name/}Fail2ban (Docker)"
        fi
        if docker ps --format '{{.Image}}' 2>/dev/null | grep -qi "crowdsec"; then
            ips_installed=true
            ips_active=true
            ips_name="${ips_name:+$ips_name/}CrowdSec (Docker)"
        fi
    fi

    if [[ "$ips_active" == "true" ]]; then
        check_security "Intrusion Prevention" "PASS" "$ips_name is installed and running" ""
    elif [[ "$ips_installed" == "true" ]]; then
        check_security "Intrusion Prevention" "WARN" "$ips_name is installed but not running" \
            "Start the intrusion prevention service"
    else
        check_security "Intrusion Prevention" "FAIL" "No intrusion prevention system found" \
            "Install fail2ban or crowdsec"
    fi
}

# =============================================================================
# AUTO-UPDATES CHECK (Issue #14)
# =============================================================================

check_auto_updates() {
    should_run_check "updates" || return 0

    local auto_updates=false
    local update_tool=""

    case "${OS_INFO[pkg_manager]}" in
        apt)
            if pkg_installed unattended-upgrades; then
                auto_updates=true
                update_tool="unattended-upgrades"
            fi
            ;;
        dnf)
            if pkg_installed dnf-automatic; then
                if service_is_active dnf-automatic.timer 2>/dev/null; then
                    auto_updates=true
                    update_tool="dnf-automatic"
                fi
            fi
            ;;
        yum)
            if pkg_installed yum-cron; then
                if service_is_active yum-cron 2>/dev/null; then
                    auto_updates=true
                    update_tool="yum-cron"
                fi
            fi
            ;;
        *)
            check_security "Unattended Upgrades" "WARN" "Cannot check auto-updates for ${OS_INFO[pkg_manager]}" ""
            return
            ;;
    esac

    if [[ "$auto_updates" == "true" ]]; then
        check_security "Unattended Upgrades" "PASS" "Automatic security updates configured ($update_tool)" ""
    else
        check_security "Unattended Upgrades" "WARN" "Automatic security updates not configured" \
            "Install and configure automatic security updates"
    fi
}

# =============================================================================
# SYSTEM UPDATES CHECK (Issue #27)
# =============================================================================

check_system_updates() {
    should_run_check "updates" || return 0

    show_progress "Checking for system updates"

    local total_updates
    local security_updates

    total_updates=$(get_update_count)
    security_updates=$(get_security_update_count)

    clear_progress

    if ! is_numeric "$total_updates"; then
        check_security "System Updates" "WARN" "Unable to determine update status" \
            "Check package manager manually"
        return
    fi

    if [[ $total_updates -eq 0 ]]; then
        check_security "System Updates" "PASS" "All packages are up to date" ""
    elif is_numeric "$security_updates" && [[ $security_updates -gt 0 ]]; then
        check_security "System Updates" "FAIL" "$security_updates security updates available (${total_updates} total)" \
            "Run system updates immediately" "true"
    else
        check_security "System Updates" "WARN" "$total_updates updates available" \
            "Schedule system updates soon"
    fi
}

# =============================================================================
# FAILED LOGINS CHECK (Issue #26)
# =============================================================================

check_failed_logins() {
    should_run_check "logins" || return 0

    local failed_count=0
    local log_source=""

    # Try journalctl first (most reliable on systemd)
    if [[ "${OS_INFO[service_manager]}" == "systemd" ]] && command -v journalctl &>/dev/null; then
        failed_count=$(journalctl -u sshd -u ssh --since "24 hours ago" 2>/dev/null | \
            grep -c "Failed password" 2>/dev/null || echo "0")
        # Clean up the count - remove any whitespace/newlines
        failed_count=$(echo "$failed_count" | tr -d '[:space:]')
        if is_numeric "$failed_count" && [[ $failed_count -gt 0 ]]; then
            log_source="journalctl (last 24h)"
        fi
    fi

    # Ensure failed_count is valid before comparison
    if ! is_numeric "$failed_count"; then
        failed_count=0
    fi

    # Fall back to log files if journalctl didn't find anything
    if [[ $failed_count -eq 0 ]]; then
        local log_files=(
            "${OS_INFO[auth_log]}"
            "/var/log/auth.log"
            "/var/log/secure"
            "/var/log/messages"
        )

        for log_file in "${log_files[@]}"; do
            if [[ -f "$log_file" ]] && [[ -r "$log_file" ]]; then
                # Get today's entries only
                local today
                today=$(date +"%b %e" | sed 's/  / /')
                failed_count=$(grep "$today" "$log_file" 2>/dev/null | grep -c "Failed password" 2>/dev/null || echo "0")
                failed_count=$(echo "$failed_count" | tr -d '[:space:]')
                if ! is_numeric "$failed_count"; then
                    failed_count=0
                fi
                if [[ $failed_count -gt 0 ]] || [[ -f "$log_file" ]]; then
                    log_source="$log_file (today)"
                    break
                fi
            fi
        done
    fi

    if [[ -z "$log_source" ]]; then
        check_security "Failed Logins" "WARN" "Unable to read authentication logs" \
            "Check log file permissions"
        return
    fi

    if [[ $failed_count -lt ${THRESHOLDS[failed_logins_warn]} ]]; then
        check_security "Failed Logins" "PASS" "$failed_count failed attempts detected ($log_source)" ""
    elif [[ $failed_count -lt ${THRESHOLDS[failed_logins_fail]} ]]; then
        check_security "Failed Logins" "WARN" "$failed_count failed attempts detected ($log_source)" \
            "Review authentication logs for suspicious activity"
    else
        check_security "Failed Logins" "FAIL" "$failed_count failed attempts detected ($log_source)" \
            "Investigate possible brute force attack immediately"
    fi
}

# =============================================================================
# RUNNING SERVICES CHECK (Issue #19)
# =============================================================================

check_running_services() {
    should_run_check "services" || return 0

    local service_count
    service_count=$(get_running_services_count)

    if ! is_numeric "$service_count"; then
        check_security "Running Services" "WARN" "Unable to count running services" ""
        return
    fi

    if [[ $service_count -lt ${THRESHOLDS[services_warn]} ]]; then
        check_security "Running Services" "PASS" "Running $service_count services - minimal attack surface" ""
    elif [[ $service_count -lt ${THRESHOLDS[services_fail]} ]]; then
        check_security "Running Services" "WARN" "$service_count services running" \
            "Review and disable unnecessary services"
    else
        check_security "Running Services" "FAIL" "Too many services running ($service_count)" \
            "Disable unnecessary services to reduce attack surface"
    fi
}

# =============================================================================
# PORT SECURITY CHECK (Issue #20)
# =============================================================================

check_open_ports() {
    should_run_check "ports" || return 0

    local listening_info=""

    # Get listening ports (prefer ss over netstat)
    if command -v ss &>/dev/null; then
        listening_info=$(ss -tuln state listening 2>/dev/null)
    elif command -v netstat &>/dev/null; then
        listening_info=$(netstat -tuln 2>/dev/null | grep LISTEN)
    else
        check_security "Port Security" "WARN" "Neither ss nor netstat available" \
            "Install iproute2 or net-tools"
        return
    fi

    if [[ -z "$listening_info" ]]; then
        check_security "Port Security" "WARN" "Unable to retrieve listening ports" ""
        return
    fi

    # Parse and categorize ports
    local -A localhost_ports=()
    local -A public_ports=()
    local -A all_ports=()

    while read -r line; do
        # Skip headers
        [[ "$line" =~ ^Netid ]] || [[ "$line" =~ ^Proto ]] || [[ "$line" =~ ^State ]] && continue
        [[ -z "$line" ]] && continue

        local addr="" port=""

        # Parse address:port - handle various formats
        # ss format: *:22, 0.0.0.0:22, [::]:22, 127.0.0.1:22
        # netstat format: 0.0.0.0:22, :::22, 127.0.0.1:22

        local listen_addr
        if command -v ss &>/dev/null; then
            listen_addr=$(echo "$line" | awk '{print $5}')
        else
            listen_addr=$(echo "$line" | awk '{print $4}')
        fi

        # Extract port (last number after last colon)
        port=$(echo "$listen_addr" | rev | cut -d: -f1 | rev)

        # Extract address (everything before last colon)
        addr=$(echo "$listen_addr" | rev | cut -d: -f2- | rev)

        # Skip if port is not numeric
        is_numeric "$port" || continue

        all_ports[$port]=1

        # Categorize by binding address
        case "$addr" in
            127.0.0.1|::1|\[::1\]|localhost)
                localhost_ports[$port]=1
                ;;
            0.0.0.0|*|\[::\]|::)
                public_ports[$port]=1
                ;;
            *)
                # Check if it's a private network address
                if [[ "$addr" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|fe80:|fc|fd) ]]; then
                    localhost_ports[$port]=1
                else
                    public_ports[$port]=1
                fi
                ;;
        esac
    done <<< "$listening_info"

    local total_count=${#all_ports[@]}
    local public_count=${#public_ports[@]}
    local localhost_count=${#localhost_ports[@]}

    # Format port lists
    local public_list=""
    if [[ ${#public_ports[@]} -gt 0 ]]; then
        public_list=$(echo "${!public_ports[@]}" | tr ' ' ',' | sed 's/,$//')
    fi

    # Evaluate security based on thresholds
    if [[ $public_count -lt ${THRESHOLDS[public_ports_warn]} ]] && \
       [[ $total_count -lt ${THRESHOLDS[ports_warn]} ]]; then
        check_security "Port Security" "PASS" \
            "Good configuration - Total: $total_count, Public: $public_count${public_list:+ ($public_list)}, Localhost: $localhost_count" ""
    elif [[ $public_count -lt ${THRESHOLDS[public_ports_fail]} ]] && \
         [[ $total_count -lt ${THRESHOLDS[ports_fail]} ]]; then
        check_security "Port Security" "WARN" \
            "Review recommended - Total: $total_count, Public: $public_count${public_list:+ ($public_list)}" \
            "Review and close unnecessary public ports"
    else
        check_security "Port Security" "FAIL" \
            "High exposure - Total: $total_count, Public: $public_count${public_list:+ ($public_list)}" \
            "Close unnecessary ports and bind services to localhost where possible"
    fi
}

# =============================================================================
# RESOURCE USAGE CHECKS
# =============================================================================

check_disk_usage() {
    should_run_check "resources" || return 0

    local disk_info
    disk_info=$(df -h / 2>/dev/null | awk 'NR==2')

    if [[ -z "$disk_info" ]]; then
        check_security "Disk Usage" "WARN" "Unable to determine disk usage" ""
        return
    fi

    local disk_total disk_used disk_avail disk_usage
    disk_total=$(echo "$disk_info" | awk '{print $2}')
    disk_used=$(echo "$disk_info" | awk '{print $3}')
    disk_avail=$(echo "$disk_info" | awk '{print $4}')
    disk_usage=$(echo "$disk_info" | awk '{print int($5)}')

    if ! is_numeric "$disk_usage"; then
        check_security "Disk Usage" "WARN" "Unable to parse disk usage" ""
        return
    fi

    local message="${disk_usage}% used (Used: ${disk_used} of ${disk_total}, Available: ${disk_avail})"

    if [[ $disk_usage -lt ${THRESHOLDS[disk_warn]} ]]; then
        check_security "Disk Usage" "PASS" "Healthy disk space - $message" ""
    elif [[ $disk_usage -lt ${THRESHOLDS[disk_fail]} ]]; then
        check_security "Disk Usage" "WARN" "Moderate disk usage - $message" \
            "Clean up disk space soon"
    else
        check_security "Disk Usage" "FAIL" "Critical disk usage - $message" \
            "Free up disk space immediately"
    fi
}

check_memory_usage() {
    should_run_check "resources" || return 0

    local mem_percent
    mem_percent=$(get_memory_stats "percent")

    if ! is_numeric "$mem_percent"; then
        check_security "Memory Usage" "WARN" "Unable to determine memory usage" ""
        return
    fi

    local mem_total mem_used mem_avail
    mem_total=$(get_memory_stats "total_human")
    mem_used=$(get_memory_stats "used_human")
    mem_avail=$(get_memory_stats "available_human")

    local message="${mem_percent}% used (Used: ${mem_used:-?} of ${mem_total:-?}, Available: ${mem_avail:-?})"

    if [[ $mem_percent -lt ${THRESHOLDS[mem_warn]} ]]; then
        check_security "Memory Usage" "PASS" "Healthy memory usage - $message" ""
    elif [[ $mem_percent -lt ${THRESHOLDS[mem_fail]} ]]; then
        check_security "Memory Usage" "WARN" "Moderate memory usage - $message" \
            "Monitor memory usage"
    else
        check_security "Memory Usage" "FAIL" "Critical memory usage - $message" \
            "Investigate memory usage and consider adding more RAM"
    fi
}

check_cpu_usage() {
    should_run_check "resources" || return 0

    # Get CPU usage from /proc/stat (more reliable than top)
    local cpu_usage=0

    if [[ -f /proc/stat ]]; then
        # Read CPU stats twice with a small delay for accurate measurement
        local cpu1 cpu2
        cpu1=$(head -1 /proc/stat | awk '{print $2+$3+$4, $5}')
        sleep 0.5
        cpu2=$(head -1 /proc/stat | awk '{print $2+$3+$4, $5}')

        local active1 idle1 active2 idle2
        read -r active1 idle1 <<< "$cpu1"
        read -r active2 idle2 <<< "$cpu2"

        local active_diff=$((active2 - active1))
        local idle_diff=$((idle2 - idle1))
        local total_diff=$((active_diff + idle_diff))

        if [[ $total_diff -gt 0 ]]; then
            cpu_usage=$((active_diff * 100 / total_diff))
        fi
    else
        # Fallback to top
        cpu_usage=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print int($2)}')
    fi

    if ! is_numeric "$cpu_usage"; then
        check_security "CPU Usage" "WARN" "Unable to determine CPU usage" ""
        return
    fi

    local cpu_cores load_avg
    cpu_cores=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 1)
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk -F',' '{print $1}' | tr -d ' ')

    local message="${cpu_usage}% used (Cores: ${cpu_cores}, Load: ${load_avg:-?})"

    if [[ $cpu_usage -lt ${THRESHOLDS[cpu_warn]} ]]; then
        check_security "CPU Usage" "PASS" "Healthy CPU usage - $message" ""
    elif [[ $cpu_usage -lt ${THRESHOLDS[cpu_fail]} ]]; then
        check_security "CPU Usage" "WARN" "Moderate CPU usage - $message" \
            "Monitor CPU usage for sustained high utilization"
    else
        check_security "CPU Usage" "FAIL" "Critical CPU usage - $message" \
            "Investigate CPU-intensive processes"
    fi
}

# =============================================================================
# SUDO LOGGING CHECK (Issue #7)
# =============================================================================

check_sudo_logging() {
    should_run_check "sudo" || return 0

    local logging_enabled=false
    local sudoers_files=("/etc/sudoers")

    # Add sudoers.d files
    if [[ -d /etc/sudoers.d ]]; then
        while IFS= read -r -d '' file; do
            sudoers_files+=("$file")
        done < <(find /etc/sudoers.d -type f -print0 2>/dev/null)
    fi

    # Check each file for logging configuration
    for sudoers_file in "${sudoers_files[@]}"; do
        if [[ -r "$sudoers_file" ]]; then
            if grep -qE "^Defaults[[:space:]]+(log|syslog)" "$sudoers_file" 2>/dev/null; then
                logging_enabled=true
                log_debug "Sudo logging found in: $sudoers_file"
                break
            fi
        fi
    done

    # On systemd systems, sudo logs to journal by default
    if [[ "${OS_INFO[service_manager]}" == "systemd" ]]; then
        logging_enabled=true
    fi

    if [[ "$logging_enabled" == "true" ]]; then
        check_security "Sudo Logging" "PASS" "Sudo commands are being logged" ""
    else
        check_security "Sudo Logging" "WARN" "Sudo logging not explicitly configured" \
            "Add 'Defaults logfile=/var/log/sudo.log' to /etc/sudoers"
    fi
}

# =============================================================================
# PASSWORD POLICY CHECK (Issue #30)
# =============================================================================

check_password_policy() {
    should_run_check "password" || return 0

    local policy_score=0
    local max_score=5
    local issues=()

    # Check pwquality.conf
    if [[ -f "/etc/security/pwquality.conf" ]]; then
        local minlen
        minlen=$(grep "^minlen" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')

        if is_numeric "$minlen" && [[ $minlen -ge 12 ]]; then
            ((policy_score++)) || true
        else
            issues+=("minlen<12")
        fi

        # Check complexity requirements (negative value means required)
        local dcredit ucredit lcredit ocredit
        dcredit=$(grep "^dcredit" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
        ucredit=$(grep "^ucredit" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
        lcredit=$(grep "^lcredit" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
        ocredit=$(grep "^ocredit" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')

        if is_numeric "$dcredit" && [[ $dcredit -lt 0 ]]; then
            ((policy_score++)) || true
        else
            issues+=("no-digit-req")
        fi

        if is_numeric "$ucredit" && [[ $ucredit -lt 0 ]]; then
            ((policy_score++)) || true
        else
            issues+=("no-upper-req")
        fi

        if is_numeric "$lcredit" && [[ $lcredit -lt 0 ]]; then
            ((policy_score++)) || true
        else
            issues+=("no-lower-req")
        fi

        if is_numeric "$ocredit" && [[ $ocredit -lt 0 ]]; then
            ((policy_score++)) || true
        else
            issues+=("no-special-req")
        fi
    else
        issues+=("pwquality.conf-missing")
    fi

    # Report results
    if [[ $policy_score -ge 4 ]]; then
        check_security "Password Policy" "PASS" "Strong password policy (score: $policy_score/$max_score)" ""
    elif [[ $policy_score -ge 2 ]]; then
        check_security "Password Policy" "WARN" "Moderate password policy (score: $policy_score/$max_score)" \
            "Configure /etc/security/pwquality.conf: ${issues[*]}"
    else
        check_security "Password Policy" "FAIL" "Weak password policy" \
            "Install libpam-pwquality and configure password requirements"
    fi
}

# =============================================================================
# SUID FILES CHECK (Issue #31, #8)
# =============================================================================

check_suid_files() {
    should_run_check "suid" || return 0

    if [[ "${CONFIG[skip_suid_scan]}" == "true" ]]; then
        log_verbose "Skipping SUID scan (--no-suid flag)"
        return
    fi

    show_progress "Scanning for SUID files"

    # Extended list of known safe SUID binaries
    local known_safe_suid=(
        "/usr/bin/sudo" "/usr/bin/su" "/usr/bin/passwd" "/usr/bin/chsh"
        "/usr/bin/chfn" "/usr/bin/newgrp" "/usr/bin/gpasswd" "/usr/bin/mount"
        "/usr/bin/umount" "/usr/bin/ping" "/usr/bin/ping6" "/usr/bin/pkexec"
        "/usr/bin/crontab" "/usr/bin/at" "/usr/bin/expiry" "/usr/bin/chage"
        "/usr/bin/wall" "/usr/bin/write" "/usr/bin/ssh-agent" "/usr/bin/staprun"
        "/usr/bin/fusermount" "/usr/bin/fusermount3"
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
        "/usr/lib/openssh/ssh-keysign"
        "/usr/lib/policykit-1/polkit-agent-helper-1"
        "/usr/libexec/polkit-agent-helper-1"
        "/usr/sbin/pppd" "/usr/sbin/unix_chkpwd" "/usr/sbin/postdrop"
        "/usr/sbin/postqueue"
        # Compatibility paths
        "/bin/su" "/bin/mount" "/bin/umount" "/bin/ping" "/bin/ping6"
        "/sbin/unix_chkpwd"
    )

    # Build exclusion pattern
    local exclude_pattern
    exclude_pattern=$(printf "|%s" "${known_safe_suid[@]}")
    exclude_pattern="(${exclude_pattern:1})$"

    # Find SUID files, using -xdev to stay on same filesystem (Issue #8)
    local suspicious_suid=()
    while IFS= read -r file; do
        if [[ -n "$file" ]] && ! echo "$file" | grep -qE "$exclude_pattern"; then
            suspicious_suid+=("$file")
        fi
    done < <(find / -xdev -type f -perm -4000 2>/dev/null)

    clear_progress

    local suid_count=${#suspicious_suid[@]}

    if [[ $suid_count -eq 0 ]]; then
        check_security "SUID Files" "PASS" "No unexpected SUID files found" ""
    elif [[ $suid_count -lt 5 ]]; then
        local files_list="${suspicious_suid[*]}"
        check_security "SUID Files" "WARN" "Found $suid_count SUID files to review: $files_list" \
            "Verify these SUID files are legitimate"
    else
        check_security "SUID Files" "WARN" "Found $suid_count unexpected SUID files" \
            "Review SUID files for security - see report for full list"
        # Log all to report
        for file in "${suspicious_suid[@]}"; do
            echo "  SUID file: $file" >> "$REPORT_FILE"
        done
    fi
}

# =============================================================================
# SYSTEM RESTART CHECK
# =============================================================================

check_system_restart() {
    should_run_check "system" || return 0

    local needs_restart=false

    # Check for reboot-required file (Debian/Ubuntu)
    if [[ -f /var/run/reboot-required ]]; then
        needs_restart=true
    fi

    # Check for needs-restarting (RHEL/CentOS/Fedora)
    if command -v needs-restarting &>/dev/null; then
        if needs-restarting -r &>/dev/null; then
            : # No reboot needed
        else
            needs_restart=true
        fi
    fi

    if [[ "$needs_restart" == "true" ]]; then
        check_security "System Restart" "WARN" "System requires a restart to apply updates" \
            "Schedule a system restart"
    else
        check_security "System Restart" "PASS" "No restart required" ""
    fi
}

# =============================================================================
# NEW SECURITY CHECKS - PHASE 7
# =============================================================================

# MAC Status Check (Issue #46)
check_mac_status() {
    should_run_check "mac" || return 0

    local mac_system=""
    local mac_status=""

    # Check SELinux
    if command -v getenforce &>/dev/null; then
        mac_status=$(getenforce 2>/dev/null || echo "Unknown")

        case "$mac_status" in
            Enforcing)
                check_security "Mandatory Access Control" "PASS" "SELinux is enforcing" ""
                return
                ;;
            Permissive)
                check_security "Mandatory Access Control" "WARN" "SELinux is in permissive mode" \
                    "Consider setting SELinux to enforcing mode"
                return
                ;;
            Disabled)
                mac_system="SELinux (disabled)"
                ;;
        esac
    fi

    # Check AppArmor
    if command -v aa-status &>/dev/null; then
        if aa-status --enabled &>/dev/null 2>&1; then
            local profiles
            profiles=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}')
            if is_numeric "$profiles" && [[ $profiles -gt 0 ]]; then
                check_security "Mandatory Access Control" "PASS" "AppArmor active with $profiles profiles" ""
                return
            fi
        fi
        check_security "Mandatory Access Control" "WARN" "AppArmor installed but not active" \
            "Enable AppArmor profiles"
        return
    fi

    check_security "Mandatory Access Control" "WARN" "No MAC system (SELinux/AppArmor) detected" \
        "Consider enabling SELinux or AppArmor"
}

# Kernel Hardening Check (Issue #49)
check_kernel_hardening() {
    should_run_check "kernel" || return 0

    local hardening_score=0
    local max_score=6
    local issues=()

    declare -A kernel_settings=(
        ["kernel.randomize_va_space"]="2"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.conf.all.rp_filter"]="1"
        ["net.ipv4.conf.default.rp_filter"]="1"
        ["kernel.kptr_restrict"]="1"
        ["kernel.dmesg_restrict"]="1"
    )

    for setting in "${!kernel_settings[@]}"; do
        local expected="${kernel_settings[$setting]}"
        local actual
        actual=$(sysctl -n "$setting" 2>/dev/null || echo "")

        if [[ "$actual" == "$expected" ]]; then
            ((hardening_score++)) || true
        else
            issues+=("${setting}=${actual:-unset}")
        fi
    done

    if [[ $hardening_score -eq $max_score ]]; then
        check_security "Kernel Hardening" "PASS" "All kernel hardening settings configured ($hardening_score/$max_score)" ""
    elif [[ $hardening_score -ge $((max_score / 2)) ]]; then
        check_security "Kernel Hardening" "WARN" "Partial kernel hardening ($hardening_score/$max_score)" \
            "Configure sysctl settings: ${issues[*]}"
    else
        check_security "Kernel Hardening" "FAIL" "Weak kernel hardening ($hardening_score/$max_score)" \
            "Apply kernel hardening settings via sysctl"
    fi
}

# User Account Auditing (Issue #50)
check_user_accounts() {
    should_run_check "users" || return 0

    local issues=()

    # Check for multiple UID 0 accounts
    local uid0_count
    uid0_count=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null | wc -l)
    if [[ $uid0_count -gt 1 ]]; then
        local uid0_users
        uid0_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        issues+=("Multiple UID 0: $uid0_users")
    fi

    # Check for users with empty passwords (if readable)
    if [[ -r /etc/shadow ]]; then
        local empty_pass
        empty_pass=$(awk -F: '($2 == "" || $2 == "!!" || $2 == "!") && $1 != "+" {print $1}' /etc/shadow 2>/dev/null | wc -l)
        # This is normal for locked system accounts, so only warn if there are many
        log_debug "Accounts with empty/locked passwords: $empty_pass"
    fi

    # Check for system users with login shells
    local system_login_shells
    system_login_shells=$(awk -F: '$3 < 1000 && $3 != 0 && $7 !~ /nologin|false|sync|shutdown|halt/ {print $1}' /etc/passwd 2>/dev/null | wc -l)
    if [[ $system_login_shells -gt 0 ]]; then
        issues+=("$system_login_shells system accounts with login shells")
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "User Accounts" "PASS" "No user account issues found" ""
    else
        check_security "User Accounts" "WARN" "Issues found: ${issues[*]}" \
            "Review user accounts and permissions"
    fi
}

# World-Writable Files Check (Issue #52)
check_world_writable() {
    should_run_check "files" || return 0

    show_progress "Checking for world-writable files"

    # Find world-writable directories without sticky bit (more concerning)
    local ww_dirs
    ww_dirs=$(find / -xdev -type d -perm -0002 ! -perm -1000 \
        ! -path "/tmp" ! -path "/var/tmp" ! -path "/dev/shm" \
        2>/dev/null | head -10)

    local ww_dir_count=0
    if [[ -n "$ww_dirs" ]]; then
        ww_dir_count=$(echo "$ww_dirs" | grep -c "^/" || echo 0)
    fi

    clear_progress

    if [[ $ww_dir_count -eq 0 ]]; then
        check_security "World-Writable" "PASS" "No dangerous world-writable directories found" ""
    else
        check_security "World-Writable" "WARN" "Found $ww_dir_count world-writable directories without sticky bit" \
            "Review and fix permissions on world-writable directories"
        echo "World-writable directories:" >> "$REPORT_FILE"
        echo "$ww_dirs" >> "$REPORT_FILE"
    fi
}

# Time Synchronization Check (Issue #54)
check_time_sync() {
    should_run_check "time" || return 0

    local ntp_active=false
    local ntp_service=""

    # Check systemd-timesyncd
    if service_is_active systemd-timesyncd 2>/dev/null; then
        ntp_active=true
        ntp_service="systemd-timesyncd"
    fi

    # Check chronyd
    if [[ "$ntp_active" == "false" ]] && service_is_active chronyd 2>/dev/null; then
        ntp_active=true
        ntp_service="chronyd"
    fi

    # Check ntpd
    if [[ "$ntp_active" == "false" ]]; then
        if service_is_active ntpd 2>/dev/null || service_is_active ntp 2>/dev/null; then
            ntp_active=true
            ntp_service="ntpd"
        fi
    fi

    # Check timedatectl status
    if [[ "$ntp_active" == "false" ]] && command -v timedatectl &>/dev/null; then
        if timedatectl show --property=NTP --value 2>/dev/null | grep -qi "yes"; then
            ntp_active=true
            ntp_service="timedatectl"
        fi
    fi

    if [[ "$ntp_active" == "true" ]]; then
        check_security "Time Sync" "PASS" "Time synchronization active ($ntp_service)" ""
    else
        check_security "Time Sync" "WARN" "No time synchronization detected" \
            "Configure time synchronization (chronyd, ntpd, or systemd-timesyncd)"
    fi
}

# Audit System Check (Issue #55)
check_audit_system() {
    should_run_check "audit" || return 0

    if pkg_installed auditd || pkg_installed audit; then
        if service_is_active auditd; then
            local rule_count=0
            if command -v auditctl &>/dev/null; then
                rule_count=$(auditctl -l 2>/dev/null | grep -c "^-" || echo 0)
            fi

            if [[ $rule_count -gt 0 ]]; then
                check_security "Audit System" "PASS" "auditd active with $rule_count rules" ""
            else
                check_security "Audit System" "WARN" "auditd running but no rules configured" \
                    "Configure audit rules for security monitoring"
            fi
        else
            check_security "Audit System" "WARN" "auditd installed but not running" \
                "Start and enable auditd service"
        fi
    else
        check_security "Audit System" "WARN" "Audit daemon (auditd) not installed" \
            "Install auditd for security auditing"
    fi
}

# Core Dump Settings Check (Issue #62)
check_core_dumps() {
    should_run_check "core" || return 0

    local core_disabled=false

    # Check ulimit
    local core_limit
    core_limit=$(ulimit -c 2>/dev/null || echo "unknown")

    if [[ "$core_limit" == "0" ]]; then
        core_disabled=true
    fi

    # Check /etc/security/limits.conf
    if grep -qE "^\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0" /etc/security/limits.conf 2>/dev/null; then
        core_disabled=true
    fi

    # Check sysctl
    local suid_dumpable
    suid_dumpable=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "")

    if [[ "$core_disabled" == "true" ]] || [[ "$suid_dumpable" == "0" ]]; then
        check_security "Core Dumps" "PASS" "Core dumps are restricted" ""
    else
        check_security "Core Dumps" "WARN" "Core dumps may be enabled" \
            "Disable core dumps to prevent sensitive data leakage"
    fi
}

# Public IP Check (Issue #4)
get_public_ip() {
    if [[ "${CONFIG[skip_network]}" == "true" ]]; then
        echo "(network checks skipped)"
        return
    fi

    local ip=""
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me"
        "https://icanhazip.com"
    )

    for service in "${services[@]}"; do
        ip=$(curl -s --max-time 5 --retry 1 "$service" 2>/dev/null | tr -d '[:space:]')

        # Validate IP format
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"
            return
        fi
    done

    echo "(unable to determine)"
}

# =============================================================================
# SUMMARY AND RECOMMENDATIONS (Issues #69, #70, #71)
# =============================================================================

print_summary() {
    local total=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))

    output ""
    output "================================"
    output "${BOLD}Audit Summary${NC}"
    output "================================"
    output "${GREEN}PASS:${NC} $PASS_COUNT"
    output "${YELLOW}WARN:${NC} $WARN_COUNT"
    output "${RED}FAIL:${NC} $FAIL_COUNT"
    output ""
    output "Total checks: $total"

    if [[ $total -gt 0 ]]; then
        local score=$((PASS_COUNT * 100 / total))
        output "Security Score: ${BOLD}${score}%${NC}"
    fi

    # Write to report
    {
        echo ""
        echo "================================"
        echo "AUDIT SUMMARY"
        echo "================================"
        echo "PASS: $PASS_COUNT"
        echo "WARN: $WARN_COUNT"
        echo "FAIL: $FAIL_COUNT"
        echo "Total: $total"
        [[ $total -gt 0 ]] && echo "Security Score: $((PASS_COUNT * 100 / total))%"
    } >> "$REPORT_FILE"
}

print_recommendations() {
    if [[ ${#RECOMMENDATIONS[@]} -eq 0 ]]; then
        return
    fi

    output ""
    output "================================"
    output "${BOLD}Recommended Actions${NC}"
    output "================================"

    local i=1
    for rec in "${RECOMMENDATIONS[@]}"; do
        output "${YELLOW}$i.${NC} $rec"
        ((i++))
    done

    # Write to report
    {
        echo ""
        echo "================================"
        echo "RECOMMENDED ACTIONS"
        echo "================================"
        local j=1
        for rec in "${RECOMMENDATIONS[@]}"; do
            echo "$j. $rec"
            ((j++))
        done
    } >> "$REPORT_FILE"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Parse command line arguments first (before root check for --help)
    parse_args "$@"

    # Initialize colors (after parsing args to respect --quiet)
    init_colors

    # Check for dry-run mode
    if [[ "${CONFIG[dry_run]}" == "true" ]]; then
        output "${BOLD}VPS Security Audit Tool v${VERSION}${NC} (DRY RUN)"
        output "The following checks would be performed:"
        output ""

        local checks=(
            "system:System restart check"
            "ssh:SSH configuration checks"
            "firewall:Firewall status check"
            "ips:Intrusion prevention check"
            "updates:System updates check"
            "logins:Failed login attempts check"
            "services:Running services check"
            "ports:Open ports check"
            "resources:Resource usage checks"
            "sudo:Sudo logging check"
            "password:Password policy check"
            "suid:SUID files scan"
            "mac:SELinux/AppArmor check"
            "kernel:Kernel hardening check"
            "users:User account audit"
            "files:World-writable files check"
            "time:Time synchronization check"
            "audit:Audit system check"
            "core:Core dump settings check"
        )

        for check in "${checks[@]}"; do
            local name="${check%%:*}"
            local desc="${check#*:}"
            if [[ "${CONFIG[checks]}" == "all" ]] || [[ ",${CONFIG[checks]}," =~ ,$name, ]]; then
                output "  [x] $desc"
            else
                output "  [ ] $desc (skipped)"
            fi
        done

        exit 0
    fi

    # Check root privileges (Issue #9)
    check_root

    # Load configuration
    load_config

    # Detect OS (Issue #64)
    detect_os

    # Create secure report file (Issues #2, #3)
    create_report_file

    # Disable cleanup on error now that we're past initialization
    CLEANUP_ON_ERROR=false

    # Initialize JSON output if needed
    if [[ "${CONFIG[output_format]}" == "json" ]] || [[ "${CONFIG[output_format]}" == "both" ]]; then
        init_json
    fi

    # Print header
    output "${BLUE}${BOLD}VPS Security Audit Tool v${VERSION}${NC}"
    output "${GRAY}https://github.com/vernu/vps-audit${NC}"
    output "${GRAY}Starting audit at $(date)${NC}"
    output ""

    # Write header to report
    {
        echo "VPS Security Audit Tool v${VERSION}"
        echo "https://github.com/vernu/vps-audit"
        echo "Starting audit at $(date)"
        echo "================================"
        echo ""
        echo "System: ${OS_INFO[name]}"
        echo "Kernel: $(uname -r)"
        echo "Hostname: $(hostname)"
        echo ""
    } >> "$REPORT_FILE"

    # System Information Section
    print_header "System Information"

    local hostname kernel_version uptime_info uptime_since public_ip
    local cpu_info cpu_cores total_mem total_disk load_avg

    hostname=$(hostname -f 2>/dev/null || hostname)
    kernel_version=$(uname -r)
    uptime_info=$(get_uptime)
    uptime_since=$(get_uptime_since)
    public_ip=$(get_public_ip)
    cpu_info=$(lscpu 2>/dev/null | grep "Model name" | cut -d':' -f2 | xargs || echo "Unknown")
    cpu_cores=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo "Unknown")
    total_mem=$(get_memory_stats "total_human")
    total_disk=$(df -h / 2>/dev/null | awk 'NR==2 {print $2}' || echo "Unknown")
    load_avg=$(uptime | awk -F'load average:' '{print $2}' | xargs 2>/dev/null || echo "Unknown")

    print_info "Hostname" "$hostname"
    print_info "Operating System" "${OS_INFO[name]}"
    print_info "Kernel Version" "$kernel_version"
    print_info "Uptime" "$uptime_info (since $uptime_since)"
    print_info "CPU Model" "$cpu_info"
    print_info "CPU Cores" "$cpu_cores"
    print_info "Total Memory" "$total_mem"
    print_info "Total Disk Space" "$total_disk"
    print_info "Public IP" "$public_ip"
    print_info "Load Average" "$load_avg"

    echo "" >> "$REPORT_FILE"

    # Security Audit Section
    print_header "Security Audit Results"

    # Run all security checks
    check_system_restart
    check_ssh_root_login
    check_ssh_password_auth
    check_ssh_port
    check_firewall_status
    check_auto_updates
    check_intrusion_prevention
    check_failed_logins
    check_system_updates
    check_running_services
    check_open_ports
    check_disk_usage
    check_memory_usage
    check_cpu_usage
    check_sudo_logging
    check_password_policy
    check_suid_files

    # New security checks (Phase 7)
    check_mac_status
    check_kernel_hardening
    check_user_accounts
    check_world_writable
    check_time_sync
    check_audit_system
    check_core_dumps

    # Print summary
    print_summary
    print_recommendations

    # Finalize JSON output
    if [[ "${CONFIG[output_format]}" == "json" ]] || [[ "${CONFIG[output_format]}" == "both" ]]; then
        finalize_json
    fi

    # Final report info
    {
        echo ""
        echo "================================"
        echo "End of VPS Audit Report"
        echo "Generated: $(date)"
        echo "================================"
    } >> "$REPORT_FILE"

    output ""
    output "VPS audit complete. Report saved to: ${BOLD}$REPORT_FILE${NC}"

    # Exit with appropriate code (Issue #42)
    if [[ $CRITICAL_FAIL_COUNT -gt 0 ]]; then
        exit 2
    elif [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

# Run main function with all arguments
main "$@"
