#!/usr/bin/env bash
#
# VPS Security Audit Tool
# Version: 2.2.0
#
# Fork: https://github.com/tomtom215/vps-audit
# Original: https://github.com/vernu/vps-audit
#
# A comprehensive security and performance auditing tool for Linux VPS systems.
# Supports: Debian, Ubuntu, RHEL, CentOS, Fedora, Rocky, Alma, Arch, Alpine, openSUSE
#

# =============================================================================
# PHASE 1: CORE INFRASTRUCTURE & SAFETY
# =============================================================================

# Exit on pipeline failures (Issue #1)
# Note: We don't use set -eu because many commands intentionally may fail
# and we handle errors explicitly throughout the script
set -o pipefail

# Prevent accidental overwriting of files
set -o noclobber

# Script version for tracking (Issue #33)
readonly VERSION="2.3.0"

# Minimum required Bash version
readonly MIN_BASH_VERSION="4.0"

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
    [show_guide]="false"
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

# shellcheck disable=SC2317  # Invoked indirectly via trap
cleanup() {
    local exit_code=$?

    clear_progress

    if [[ $exit_code -ne 0 ]] && [[ "$CLEANUP_ON_ERROR" == "true" ]]; then
        if [[ -n "$REPORT_FILE" ]] && [[ -f "$REPORT_FILE" ]]; then
            rm -f "$REPORT_FILE" 2>/dev/null
            echo "Cleaned up partial report file due to error" >&2
        fi
    fi

    exit "$exit_code"
}

trap cleanup EXIT INT TERM

# =============================================================================
# INPUT VALIDATION (Issue #44, #6, #13)
# =============================================================================

is_numeric() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]]
}

# Check for a signed integer value (handles negative numbers, e.g. pwquality credits)
is_integer() {
    local value="$1"
    [[ "$value" =~ ^-?[0-9]+$ ]]
}

# shellcheck disable=SC2317  # Called from parse_args
validate_percentage() {
    local value="$1"
    is_numeric "$value" && [[ $value -le 100 ]]
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
# BASH VERSION CHECK
# =============================================================================

check_bash_version() {
    local bash_major="${BASH_VERSINFO[0]:-0}"
    local bash_minor="${BASH_VERSINFO[1]:-0}"
    local required_major="${MIN_BASH_VERSION%%.*}"
    local required_minor="${MIN_BASH_VERSION##*.}"

    if [[ $bash_major -lt $required_major ]] || \
       { [[ $bash_major -eq $required_major ]] && [[ $bash_minor -lt $required_minor ]]; }; then
        echo "ERROR: Bash version $MIN_BASH_VERSION or higher is required" >&2
        echo "Current version: ${BASH_VERSION:-unknown}" >&2
        exit 1
    fi
}

# =============================================================================
# COMMAND AVAILABILITY AND VERSION DETECTION
# =============================================================================

# Cache for command availability (improves performance)
declare -A CMD_CACHE=()

# Tool version information
declare -A TOOL_INFO=(
    [stat_type]=""          # "gnu" or "bsd"
    [ss_version]=""         # ss version
    [iptables_nft]=""       # "true" if iptables uses nftables backend
    [busybox]=""            # "true" if running in busybox environment
    [coreutils]=""          # "gnu" or "busybox" or "bsd"
)

# Fast command availability check with caching
has_command() {
    local cmd="$1"

    # Check cache first
    if [[ -n "${CMD_CACHE[$cmd]+isset}" ]]; then
        [[ "${CMD_CACHE[$cmd]}" == "1" ]]
        return
    fi

    # Check and cache
    if command -v "$cmd" &>/dev/null; then
        CMD_CACHE[$cmd]="1"
        return 0
    else
        CMD_CACHE[$cmd]="0"
        return 1
    fi
}

# Detect tool versions and variants
detect_tool_versions() {
    # Detect stat variant (GNU vs BSD)
    if has_command stat; then
        if stat --version 2>&1 | grep -q "GNU\|coreutils"; then
            TOOL_INFO[stat_type]="gnu"
        elif stat -f "%z" / &>/dev/null; then
            TOOL_INFO[stat_type]="bsd"
        else
            # Fallback: try GNU syntax first
            if stat -c '%s' / &>/dev/null 2>&1; then
                TOOL_INFO[stat_type]="gnu"
            else
                TOOL_INFO[stat_type]="bsd"
            fi
        fi
    fi

    # Detect busybox environment
    # We check --help/--version output to detect coreutils implementation
    local is_busybox=false
    local is_gnu=false

    if has_command busybox; then
        is_busybox=true
    elif has_command ls; then
        local ls_help
        ls_help=$(ls --help 2>&1 || true)
        if [[ "$ls_help" == *"BusyBox"* ]]; then
            is_busybox=true
        fi
        local ls_version
        ls_version=$(ls --version 2>&1 || true)
        if [[ "$ls_version" == *"GNU"* ]] || [[ "$ls_version" == *"coreutils"* ]]; then
            is_gnu=true
        fi
    fi

    if [[ "$is_busybox" == "true" ]]; then
        TOOL_INFO[busybox]="true"
        TOOL_INFO[coreutils]="busybox"
    elif [[ "$is_gnu" == "true" ]]; then
        TOOL_INFO[coreutils]="gnu"
    else
        TOOL_INFO[coreutils]="unknown"
    fi

    # Detect iptables backend (legacy vs nftables)
    if has_command iptables; then
        if iptables --version 2>&1 | grep -q "nf_tables"; then
            TOOL_INFO[iptables_nft]="true"
        else
            TOOL_INFO[iptables_nft]="false"
        fi
    fi

    # Get ss version if available
    if has_command ss; then
        TOOL_INFO[ss_version]=$(ss --version 2>&1 | head -1 || echo "unknown")
    fi

    log_debug "Tool detection: stat=${TOOL_INFO[stat_type]}, coreutils=${TOOL_INFO[coreutils]}, busybox=${TOOL_INFO[busybox]:-false}"
}

# =============================================================================
# PORTABLE STAT WRAPPER
# =============================================================================

# Portable stat wrapper that works on GNU and BSD systems
portable_stat() {
    local format="$1"
    local file="$2"

    if [[ ! -e "$file" ]]; then
        echo ""
        return 1
    fi

    case "${TOOL_INFO[stat_type]}" in
        gnu)
            case "$format" in
                uid)   stat -c '%u' "$file" 2>/dev/null ;;
                gid)   stat -c '%g' "$file" 2>/dev/null ;;
                mode)  stat -c '%a' "$file" 2>/dev/null ;;
                size)  stat -c '%s' "$file" 2>/dev/null ;;
                owner) stat -c '%U' "$file" 2>/dev/null ;;
                group) stat -c '%G' "$file" 2>/dev/null ;;
            esac
            ;;
        bsd)
            case "$format" in
                uid)   stat -f '%u' "$file" 2>/dev/null ;;
                gid)   stat -f '%g' "$file" 2>/dev/null ;;
                mode)  stat -f '%Lp' "$file" 2>/dev/null ;;
                size)  stat -f '%z' "$file" 2>/dev/null ;;
                owner) stat -f '%Su' "$file" 2>/dev/null ;;
                group) stat -f '%Sg' "$file" 2>/dev/null ;;
            esac
            ;;
        *)
            # Fallback: try GNU first, then BSD
            case "$format" in
                uid)   stat -c '%u' "$file" 2>/dev/null || stat -f '%u' "$file" 2>/dev/null ;;
                gid)   stat -c '%g' "$file" 2>/dev/null || stat -f '%g' "$file" 2>/dev/null ;;
                mode)  stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null ;;
                size)  stat -c '%s' "$file" 2>/dev/null || stat -f '%z' "$file" 2>/dev/null ;;
                owner) stat -c '%U' "$file" 2>/dev/null || stat -f '%Su' "$file" 2>/dev/null ;;
                group) stat -c '%G' "$file" 2>/dev/null || stat -f '%Sg' "$file" 2>/dev/null ;;
            esac
            ;;
    esac
}

# =============================================================================
# PREREQUISITES CHECK
# =============================================================================

check_prerequisites() {
    local missing_required=()
    local missing_recommended=()
    local warnings=()

    # Required commands - these are essential
    local required_cmds=("grep" "awk" "sed" "cut" "find" "stat" "mktemp" "hostname" "uname" "date")
    for cmd in "${required_cmds[@]}"; do
        if ! has_command "$cmd"; then
            missing_required+=("$cmd")
        fi
    done

    # Recommended commands - script works without but with reduced functionality
    local recommended_cmds=("curl" "ss" "sysctl" "journalctl" "df" "free" "ip")
    for cmd in "${recommended_cmds[@]}"; do
        if ! has_command "$cmd"; then
            missing_recommended+=("$cmd")
        fi
    done

    if [[ ${#missing_required[@]} -gt 0 ]]; then
        echo "ERROR: Missing required commands: ${missing_required[*]}" >&2
        echo "Please install the required packages and try again." >&2
        echo "" >&2
        echo "Installation hints:" >&2
        echo "  Debian/Ubuntu: apt install coreutils findutils grep gawk sed hostname" >&2
        echo "  RHEL/CentOS:   yum install coreutils findutils grep gawk sed hostname" >&2
        echo "  Alpine:        apk add coreutils findutils grep gawk sed" >&2
        exit 1
    fi

    # Detect tool versions and variants
    detect_tool_versions

    # Warn about busybox limitations
    if [[ "${TOOL_INFO[busybox]}" == "true" ]]; then
        warnings+=("Running in BusyBox environment - some checks may have limited functionality")
    fi

    if [[ ${#missing_recommended[@]} -gt 0 ]]; then
        warnings+=("Missing optional commands (${missing_recommended[*]}) - some checks may be skipped")
    fi

    # Print warnings if not in quiet mode
    if [[ ${#warnings[@]} -gt 0 ]] && [[ "${CONFIG[quiet]}" != "true" ]]; then
        for warn in "${warnings[@]}"; do
            echo -e "${YELLOW}[INFO]${NC} $warn" >&2
        done
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
            count=$(find /var/service -maxdepth 1 -type l 2>/dev/null | wc -l || echo 0)
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

# Properly escape a string for safe embedding in JSON (top-level so init_json can use it)
# Order matters: backslash must be escaped first before any other substitution
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"      # Escape backslashes first
    str="${str//\"/\\\"}"      # Escape double quotes
    str="${str//$'\n'/\\n}"    # Escape newlines
    str="${str//$'\r'/\\r}"    # Escape carriage returns
    str="${str//$'\t'/\\t}"    # Escape tabs
    printf '%s' "$str"
}

init_json() {
    local timestamp hostname_esc os_esc timestamp_esc
    timestamp=$(date -Iseconds 2>/dev/null || date)
    hostname_esc=$(json_escape "$(hostname)")
    os_esc=$(json_escape "${OS_INFO[name]}")
    timestamp_esc=$(json_escape "$timestamp")
    JSON_OUTPUT='{"version":"'"$VERSION"'","timestamp":"'"$timestamp_esc"'","hostname":"'"$hostname_esc"'","os":"'"$os_esc"'","checks":['
}

add_json_result() {
    local test_name="$1"
    local status="$2"
    local message="$3"

    test_name=$(json_escape "$test_name")
    message=$(json_escape "$message")

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
        # Use >| to force overwrite even with noclobber set
        printf '%s\n' "$JSON_OUTPUT" >| "$json_file"
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

A comprehensive security auditing tool for Linux VPS systems.
Run this script on a new VPS to identify security issues and harden your server.

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    -v, --version           Show version information
    -q, --quiet             Suppress console output (for cron jobs)
    -o, --output DIR        Output directory for report (default: current)
    -f, --format FORMAT     Output format: text, json, both (default: text)
    -V, --verbose           Enable verbose/debug output
    --guide                 Show quick-start hardening guide for new VPS
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

Available Check Categories:
    ssh         SSH configuration (root login, password auth, port, key permissions)
    firewall    Firewall status (UFW, firewalld, iptables, nftables)
    ips         Intrusion prevention (fail2ban, crowdsec)
    updates     System updates and auto-updates
    logins      Failed login attempts
    services    Running services analysis
    ports       Open ports detection
    resources   Disk, memory, CPU usage
    sudo        Sudo logging configuration
    password    Password policy and account lockout
    suid        SUID/SGID file scanning
    mac         SELinux/AppArmor status
    kernel      Kernel hardening (sysctl settings)
    users       User account auditing
    files       File permissions (world-writable, logs, umask)
    time        Time synchronization
    audit       Audit daemon status
    core        Core dump settings
    cron        Cron security
    network     Network protocols, IPv6, wireless

Examples:
    sudo $0                         # Run all checks
    sudo $0 --guide                 # Show hardening guide for new VPS
    sudo $0 -q -f json              # Quiet mode with JSON output
    sudo $0 --no-suid --no-network  # Skip slow/network checks
    sudo $0 --checks ssh,firewall   # Run only specific checks

Exit Codes:
    0   All checks passed (or only warnings)
    1   One or more checks failed
    2   Critical security issues found

Report bugs to: https://github.com/tomtom215/vps-audit/issues
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
            --guide)
                CONFIG[show_guide]="true"
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

    # Validate threshold relationships: warn must be strictly less than fail
    local -A threshold_pairs=(
        [disk]="disk_warn:disk_fail"
        [mem]="mem_warn:mem_fail"
        [logins]="failed_logins_warn:failed_logins_fail"
    )
    for pair in "${threshold_pairs[@]}"; do
        local warn_key="${pair%%:*}"
        local fail_key="${pair##*:}"
        if [[ ${THRESHOLDS[$warn_key]} -ge ${THRESHOLDS[$fail_key]} ]]; then
            log_error "Threshold error: ${warn_key} (${THRESHOLDS[$warn_key]}) must be less than ${fail_key} (${THRESHOLDS[$fail_key]})"
            exit 1
        fi
    done
}

# Load configuration file if exists (with security validation)
load_config() {
    local config_files=(
        "/etc/vps-audit.conf"
        "$HOME/.vps-audit.conf"
        "./.vps-audit.conf"
    )

    for config_file in "${config_files[@]}"; do
        if [[ -f "$config_file" ]] && [[ -r "$config_file" ]]; then
            # Security check: verify file ownership and permissions
            local file_owner file_perms
            file_owner=$(portable_stat uid "$config_file")
            file_perms=$(portable_stat mode "$config_file")

            # Skip if we couldn't get file info
            if [[ -z "$file_owner" ]] || [[ -z "$file_perms" ]]; then
                log_warning "Ignoring config file $config_file - could not verify ownership/permissions"
                continue
            fi

            # Config file must be owned by root or current user
            if [[ "$file_owner" != "0" ]] && [[ "$file_owner" != "$EUID" ]]; then
                log_warning "Ignoring config file $config_file - not owned by root or current user"
                continue
            fi

            # Config file should not be world-writable
            if [[ "${file_perms: -1}" =~ [2367] ]]; then
                log_warning "Ignoring config file $config_file - world-writable (insecure)"
                continue
            fi

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

        # Check if default policy is DROP/REJECT (use portable POSIX sed, not grep -P)
        local input_policy
        input_policy=$(iptables -L INPUT -n 2>/dev/null | head -1 | sed -n 's/.*policy \([A-Z]*\).*/\1/p')
        input_policy="${input_policy:-ACCEPT}"

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
        # Skip header lines and blank lines
        # Use explicit if to avoid &&/|| precedence ambiguity
        [[ -z "$line" ]] && continue
        if [[ "$line" =~ ^(Netid|Proto|State) ]]; then
            continue
        fi

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
            0.0.0.0|\[::\]|::|\[::ffff:0.0.0.0\])
                # All-zeros addresses mean listening on all interfaces (public)
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
        # Read CPU stats twice with a small delay for accurate measurement.
        # /proc/stat fields: cpu user nice system idle iowait irq softirq steal ...
        # active = user+nice+system+irq+softirq+steal (fields 2,3,4,7,8,9)
        # idle   = idle+iowait                        (fields 5,6)
        local cpu1 cpu2
        cpu1=$(head -1 /proc/stat | awk '{print $2+$3+$4+$7+$8+$9, $5+$6}')
        sleep 0.5
        cpu2=$(head -1 /proc/stat | awk '{print $2+$3+$4+$7+$8+$9, $5+$6}')

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

        # Check complexity requirements: pwquality uses negative values to require a character
        # class (e.g., dcredit=-1 means at least one digit required).  is_numeric() only
        # matches non-negative integers, so use is_integer() here to handle the minus sign.
        local dcredit ucredit lcredit ocredit
        dcredit=$(grep "^dcredit" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
        ucredit=$(grep "^ucredit" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
        lcredit=$(grep "^lcredit" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
        ocredit=$(grep "^ocredit" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')

        if is_integer "$dcredit" && [[ $dcredit -lt 0 ]]; then
            ((policy_score++)) || true
        else
            issues+=("no-digit-req")
        fi

        if is_integer "$ucredit" && [[ $ucredit -lt 0 ]]; then
            ((policy_score++)) || true
        else
            issues+=("no-upper-req")
        fi

        if is_integer "$lcredit" && [[ $lcredit -lt 0 ]]; then
            ((policy_score++)) || true
        else
            issues+=("no-lower-req")
        fi

        if is_integer "$ocredit" && [[ $ocredit -lt 0 ]]; then
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
        # Use bash regex to avoid fork+exec overhead and UUOC anti-pattern
        if [[ -n "$file" ]] && ! [[ "$file" =~ $exclude_pattern ]]; then
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
                # SELinux disabled - continue to check AppArmor
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

# =============================================================================
# PHASE 8: ADDITIONAL PRODUCTION HARDENING CHECKS
# =============================================================================

# SSH Key Permissions Check
check_ssh_key_permissions() {
    should_run_check "ssh" || return 0

    local issues=()

    # Check root SSH directory
    if [[ -d /root/.ssh ]]; then
        local root_ssh_perms
        root_ssh_perms=$(portable_stat mode /root/.ssh)
        if [[ -n "$root_ssh_perms" ]] && [[ "$root_ssh_perms" != "700" ]]; then
            issues+=("/root/.ssh has insecure permissions: $root_ssh_perms (should be 700)")
        fi

        # Check authorized_keys
        if [[ -f /root/.ssh/authorized_keys ]]; then
            local auth_perms
            auth_perms=$(portable_stat mode /root/.ssh/authorized_keys)
            if [[ -n "$auth_perms" ]] && [[ "$auth_perms" != "600" ]] && [[ "$auth_perms" != "644" ]]; then
                issues+=("/root/.ssh/authorized_keys has insecure permissions: $auth_perms")
            fi
        fi
    fi

    # Check user SSH directories
    while IFS=: read -r _username _ uid _ _ homedir _; do
        [[ $uid -lt 1000 ]] && continue
        [[ ! -d "$homedir/.ssh" ]] && continue

        local ssh_perms
        ssh_perms=$(portable_stat mode "$homedir/.ssh")
        if [[ -n "$ssh_perms" ]] && [[ "$ssh_perms" != "700" ]]; then
            issues+=("$homedir/.ssh has insecure permissions: $ssh_perms")
        fi
    done < /etc/passwd

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "SSH Key Permissions" "PASS" "SSH directories have correct permissions" ""
    else
        local issue_count=${#issues[@]}
        check_security "SSH Key Permissions" "WARN" "Found $issue_count SSH permission issues" \
            "Fix SSH directory permissions: chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
    fi
}

# SGID Files Check (complementing SUID check)
check_sgid_files() {
    should_run_check "suid" || return 0

    if [[ "${CONFIG[skip_suid_scan]}" == "true" ]]; then
        return
    fi

    show_progress "Scanning for SGID files"

    # Known safe SGID binaries
    local known_safe_sgid=(
        "/usr/bin/wall" "/usr/bin/write" "/usr/bin/ssh-agent"
        "/usr/bin/expiry" "/usr/bin/chage" "/usr/bin/crontab"
        "/usr/bin/bsd-write" "/usr/bin/mlocate"
        "/usr/sbin/unix_chkpwd" "/usr/sbin/postdrop" "/usr/sbin/postqueue"
    )

    local exclude_pattern
    exclude_pattern=$(printf "|%s" "${known_safe_sgid[@]}")
    exclude_pattern="(${exclude_pattern:1})$"

    local suspicious_sgid=()
    while IFS= read -r file; do
        # Use bash regex to avoid fork+exec overhead and UUOC anti-pattern
        if [[ -n "$file" ]] && ! [[ "$file" =~ $exclude_pattern ]]; then
            suspicious_sgid+=("$file")
        fi
    done < <(find / -xdev -type f -perm -2000 2>/dev/null)

    clear_progress

    local sgid_count=${#suspicious_sgid[@]}

    if [[ $sgid_count -eq 0 ]]; then
        check_security "SGID Files" "PASS" "No unexpected SGID files found" ""
    elif [[ $sgid_count -lt 5 ]]; then
        check_security "SGID Files" "WARN" "Found $sgid_count SGID files to review" \
            "Verify these SGID files are legitimate"
    else
        check_security "SGID Files" "WARN" "Found $sgid_count unexpected SGID files" \
            "Review SGID files for security implications"
        for file in "${suspicious_sgid[@]}"; do
            echo "  SGID file: $file" >> "$REPORT_FILE"
        done
    fi
}

# Cron Security Check
check_cron_security() {
    should_run_check "cron" || return 0

    local issues=()

    # Check cron.allow and cron.deny
    if [[ ! -f /etc/cron.allow ]] && [[ ! -f /etc/cron.deny ]]; then
        issues+=("No cron access control (cron.allow/cron.deny)")
    fi

    # Check crontab directory permissions
    for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "$crondir" ]]; then
            local perms
            perms=$(portable_stat mode "$crondir")
            if [[ -n "$perms" ]] && [[ "${perms: -1}" =~ [2367] ]]; then
                issues+=("$crondir is world-writable")
            fi
        fi
    done

    # Check for world-readable crontabs with sensitive content
    if [[ -d /var/spool/cron/crontabs ]]; then
        local perms
        perms=$(portable_stat mode /var/spool/cron/crontabs)
        if [[ -n "$perms" ]] && [[ "$perms" != "700" ]] && [[ "$perms" != "1730" ]]; then
            issues+=("/var/spool/cron/crontabs has weak permissions: $perms")
        fi
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "Cron Security" "PASS" "Cron configuration is secure" ""
    else
        check_security "Cron Security" "WARN" "Found ${#issues[@]} cron security issues" \
            "Review cron permissions and access controls"
    fi
}

# Dangerous Network Protocols Check
check_dangerous_protocols() {
    should_run_check "kernel" || return 0

    local dangerous_protocols=("dccp" "sctp" "rds" "tipc")
    local loaded_dangerous=()

    for proto in "${dangerous_protocols[@]}"; do
        if lsmod 2>/dev/null | grep -q "^$proto"; then
            loaded_dangerous+=("$proto")
        fi
    done

    # Check if protocols are blacklisted
    local blacklisted=0
    for proto in "${dangerous_protocols[@]}"; do
        if grep -rq "install $proto /bin/true\|install $proto /bin/false\|blacklist $proto" /etc/modprobe.d/ 2>/dev/null; then
            ((blacklisted++)) || true
        fi
    done

    if [[ ${#loaded_dangerous[@]} -gt 0 ]]; then
        check_security "Network Protocols" "WARN" "Dangerous protocols loaded: ${loaded_dangerous[*]}" \
            "Blacklist unnecessary protocols in /etc/modprobe.d/"
    elif [[ $blacklisted -lt ${#dangerous_protocols[@]} ]]; then
        check_security "Network Protocols" "WARN" "Some dangerous protocols not explicitly disabled" \
            "Add 'install <protocol> /bin/true' to /etc/modprobe.d/blacklist.conf"
    else
        check_security "Network Protocols" "PASS" "Dangerous protocols are disabled" ""
    fi
}

# Login Banner Check
check_login_banner() {
    should_run_check "system" || return 0

    local has_banner=false

    # Check SSH banner
    local ssh_banner
    ssh_banner=$(get_ssh_config "Banner" "none")
    if [[ "$ssh_banner" != "none" ]] && [[ -f "$ssh_banner" ]]; then
        has_banner=true
    fi

    # Check /etc/issue and /etc/issue.net
    if [[ -f /etc/issue ]] && [[ -s /etc/issue ]]; then
        local issue_content
        issue_content=$(< /etc/issue)
        # Check it's not just default content (OS name or \n/\l escape sequences)
        if [[ ! "$issue_content" =~ (Ubuntu|Debian|CentOS|Red\ Hat|\\\\n|\\\\l) ]]; then
            has_banner=true
        fi
    fi

    if [[ "$has_banner" == "true" ]]; then
        check_security "Login Banner" "PASS" "Login warning banner is configured" ""
    else
        check_security "Login Banner" "WARN" "No login warning banner configured" \
            "Configure a warning banner in /etc/issue and SSH Banner directive"
    fi
}

# Account Lockout Policy Check
check_account_lockout() {
    should_run_check "password" || return 0

    local lockout_configured=false

    # Check pam_faillock (modern) or pam_tally2 (legacy)
    if grep -rq "pam_faillock.so" /etc/pam.d/ 2>/dev/null; then
        lockout_configured=true
    elif grep -rq "pam_tally2.so" /etc/pam.d/ 2>/dev/null; then
        lockout_configured=true
    fi

    # Check fail2ban as alternative
    if service_is_active fail2ban 2>/dev/null; then
        lockout_configured=true
    fi

    if [[ "$lockout_configured" == "true" ]]; then
        check_security "Account Lockout" "PASS" "Account lockout policy is configured" ""
    else
        check_security "Account Lockout" "WARN" "No account lockout policy detected" \
            "Configure pam_faillock or fail2ban to prevent brute force attacks"
    fi
}

# Umask Settings Check
check_umask_settings() {
    should_run_check "files" || return 0

    local secure_umask=false
    local umask_value=""

    # Check /etc/login.defs
    if [[ -f /etc/login.defs ]]; then
        umask_value=$(grep "^UMASK" /etc/login.defs 2>/dev/null | awk '{print $2}')
        if [[ "$umask_value" == "027" ]] || [[ "$umask_value" == "077" ]]; then
            secure_umask=true
        fi
    fi

    # Check /etc/profile and /etc/bashrc
    for file in /etc/profile /etc/bashrc /etc/bash.bashrc; do
        if [[ -f "$file" ]]; then
            if grep -q "umask 027\|umask 077" "$file" 2>/dev/null; then
                secure_umask=true
                break
            fi
        fi
    done

    if [[ "$secure_umask" == "true" ]]; then
        check_security "Umask Settings" "PASS" "Secure umask is configured" ""
    else
        check_security "Umask Settings" "WARN" "Default umask may be too permissive" \
            "Set UMASK to 027 or 077 in /etc/login.defs"
    fi
}

# Log File Permissions Check
check_log_permissions() {
    should_run_check "files" || return 0

    local issues=()

    # Check key log files
    local log_files=(
        "/var/log/auth.log"
        "/var/log/secure"
        "/var/log/syslog"
        "/var/log/messages"
        "/var/log/kern.log"
    )

    for logfile in "${log_files[@]}"; do
        if [[ -f "$logfile" ]]; then
            local perms
            perms=$(portable_stat mode "$logfile")

            # Log files should not be world-readable for sensitive logs
            if [[ -n "$perms" ]] && [[ "${perms: -1}" =~ [4567] ]]; then
                issues+=("$logfile is world-readable")
            fi
        fi
    done

    # Check /var/log directory itself
    if [[ -d /var/log ]]; then
        local log_perms
        log_perms=$(portable_stat mode /var/log)
        if [[ -n "$log_perms" ]] && [[ "${log_perms: -1}" =~ [2367] ]]; then
            issues+=("/var/log is world-writable")
        fi
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "Log Permissions" "PASS" "Log file permissions are secure" ""
    else
        check_security "Log Permissions" "WARN" "Found ${#issues[@]} log permission issues" \
            "Restrict log file permissions (chmod 640 for sensitive logs)"
    fi
}

# Secure Boot / UEFI Check
check_secure_boot() {
    should_run_check "system" || return 0

    local secure_boot_status="unknown"

    # Check if running UEFI
    if [[ -d /sys/firmware/efi ]]; then
        # Check SecureBoot status
        local sb_file
        for sb_file in /sys/firmware/efi/efivars/SecureBoot-*; do
            if [[ -f "$sb_file" ]]; then
                local sb_value
                sb_value=$(od -An -t u1 "$sb_file" 2>/dev/null | awk '{print $NF}')
                if [[ "$sb_value" == "1" ]]; then
                    secure_boot_status="enabled"
                else
                    secure_boot_status="disabled"
                fi
                break
            fi
        done

        # Alternative check via mokutil
        if command -v mokutil &>/dev/null; then
            if mokutil --sb-state 2>/dev/null | grep -qi "SecureBoot enabled"; then
                secure_boot_status="enabled"
            fi
        fi

        if [[ "$secure_boot_status" == "enabled" ]]; then
            check_security "Secure Boot" "PASS" "UEFI Secure Boot is enabled" ""
        elif [[ "$secure_boot_status" == "disabled" ]]; then
            check_security "Secure Boot" "WARN" "UEFI Secure Boot is disabled" \
                "Consider enabling Secure Boot for enhanced boot security"
        else
            check_security "Secure Boot" "WARN" "Unable to determine Secure Boot status" ""
        fi
    else
        # Legacy BIOS - check for GRUB password
        if [[ -f /boot/grub/grub.cfg ]] || [[ -f /boot/grub2/grub.cfg ]]; then
            if grep -q "password" /etc/grub.d/* 2>/dev/null || \
               grep -q "set superusers" /etc/grub.d/* 2>/dev/null; then
                check_security "Bootloader Security" "PASS" "GRUB password is configured" ""
            else
                check_security "Bootloader Security" "WARN" "GRUB password not configured" \
                    "Configure GRUB password to prevent unauthorized boot modifications"
            fi
        fi
    fi
}

# Process Accounting Check
check_process_accounting() {
    should_run_check "audit" || return 0

    local accounting_enabled=false

    # Check for psacct/acct
    if pkg_installed psacct || pkg_installed acct; then
        if service_is_active psacct 2>/dev/null || service_is_active acct 2>/dev/null; then
            accounting_enabled=true
        fi
    fi

    # Check if lastcomm works (indicates accounting is on)
    if command -v lastcomm &>/dev/null && lastcomm 2>/dev/null | head -1 | grep -q .; then
        accounting_enabled=true
    fi

    if [[ "$accounting_enabled" == "true" ]]; then
        check_security "Process Accounting" "PASS" "Process accounting is enabled" ""
    else
        check_security "Process Accounting" "WARN" "Process accounting not enabled" \
            "Install and enable psacct/acct for command auditing"
    fi
}

# IPv6 Security Check
check_ipv6_security() {
    should_run_check "network" || return 0

    local ipv6_enabled=false
    local ipv6_configured=false

    # Check if IPv6 is enabled
    if [[ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]]; then
        local disabled
        disabled=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)
        if [[ "$disabled" == "0" ]]; then
            ipv6_enabled=true
        fi
    fi

    if [[ "$ipv6_enabled" == "true" ]]; then
        # Check if IPv6 is actually being used
        if ip -6 addr show 2>/dev/null | grep -q "inet6.*global"; then
            ipv6_configured=true
        fi

        # Check IPv6 firewall if enabled
        if [[ "$ipv6_configured" == "true" ]]; then
            if command -v ip6tables &>/dev/null; then
                local ipv6_rules
                ipv6_rules=$(ip6tables -L INPUT -n 2>/dev/null | tail -n +3 | wc -l)
                if [[ $ipv6_rules -eq 0 ]]; then
                    check_security "IPv6 Security" "WARN" "IPv6 is enabled but no firewall rules" \
                        "Configure ip6tables rules or disable IPv6 if not needed"
                    return
                fi
            fi
            check_security "IPv6 Security" "PASS" "IPv6 is enabled with firewall protection" ""
        else
            check_security "IPv6 Security" "PASS" "IPv6 enabled but not configured (safe)" ""
        fi
    else
        check_security "IPv6 Security" "PASS" "IPv6 is disabled" ""
    fi
}

# Wireless Interface Check (for servers)
check_wireless_interfaces() {
    should_run_check "network" || return 0

    local wireless_count=0

    # Check for wireless interfaces
    if command -v iw &>/dev/null; then
        wireless_count=$(iw dev 2>/dev/null | grep -c "Interface" || echo 0)
    elif [[ -d /sys/class/net ]]; then
        for iface in /sys/class/net/*; do
            if [[ -d "$iface/wireless" ]]; then
                ((wireless_count++)) || true
            fi
        done
    fi

    if [[ $wireless_count -eq 0 ]]; then
        check_security "Wireless Interfaces" "PASS" "No wireless interfaces detected (expected for server)" ""
    else
        check_security "Wireless Interfaces" "WARN" "Found $wireless_count wireless interface(s)" \
            "Disable wireless interfaces on production servers if not needed"
    fi
}

# USB Storage Restriction Check
check_usb_storage() {
    should_run_check "system" || return 0

    local usb_disabled=false

    # Check if usb-storage module is blacklisted
    if grep -rq "blacklist usb-storage\|install usb-storage /bin/true\|install usb-storage /bin/false" /etc/modprobe.d/ 2>/dev/null; then
        usb_disabled=true
    fi

    # Check if usb-storage is currently loaded
    local usb_loaded=false
    if lsmod 2>/dev/null | grep -q "usb_storage"; then
        usb_loaded=true
    fi

    if [[ "$usb_disabled" == "true" ]] && [[ "$usb_loaded" == "false" ]]; then
        check_security "USB Storage" "PASS" "USB storage is disabled" ""
    elif [[ "$usb_loaded" == "true" ]]; then
        check_security "USB Storage" "WARN" "USB storage module is loaded" \
            "Consider disabling USB storage on production servers"
    else
        check_security "USB Storage" "WARN" "USB storage not explicitly disabled" \
            "Add 'blacklist usb-storage' to /etc/modprobe.d/blacklist.conf"
    fi
}

# Compiler Access Check (production servers shouldn't have compilers)
check_compiler_access() {
    should_run_check "system" || return 0

    local compilers=("gcc" "g++" "cc" "clang" "make" "as" "ld")
    local found_compilers=()

    for compiler in "${compilers[@]}"; do
        if command -v "$compiler" &>/dev/null; then
            found_compilers+=("$compiler")
        fi
    done

    if [[ ${#found_compilers[@]} -eq 0 ]]; then
        check_security "Compiler Access" "PASS" "No compilers found (good for production)" ""
    elif [[ ${#found_compilers[@]} -lt 3 ]]; then
        check_security "Compiler Access" "WARN" "Compilers found: ${found_compilers[*]}" \
            "Consider removing compilers from production servers"
    else
        check_security "Compiler Access" "WARN" "Multiple compilers installed: ${found_compilers[*]}" \
            "Remove development tools from production systems"
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
# PHASE 9: ADVANCED SECURITY CHECKS
# =============================================================================

# Extended SSH Hardening Check
# Covers: X11Forwarding, MaxAuthTries, idle timeout, PermitEmptyPasswords,
#         AllowUsers/AllowGroups restrictions, weak cipher detection,
#         PubkeyAuthentication
check_ssh_hardening_extended() {
    should_run_check "ssh" || return 0

    local issues=()
    local score=0
    local max_score=7

    # X11Forwarding should be disabled (unnecessary attack surface)
    local x11_forward
    x11_forward=$(get_ssh_config "X11Forwarding" "yes")
    if [[ "$x11_forward" == "no" ]]; then
        ((score++)) || true
    else
        issues+=("X11Forwarding not disabled")
    fi

    # MaxAuthTries <= 3 limits per-connection brute-force attempts
    local max_tries
    max_tries=$(get_ssh_config "MaxAuthTries" "6")
    if is_numeric "$max_tries" && [[ $max_tries -le 3 ]]; then
        ((score++)) || true
    else
        issues+=("MaxAuthTries=${max_tries:-6} (should be ≤3)")
    fi

    # ClientAliveInterval enforces idle session timeout
    local alive_interval
    alive_interval=$(get_ssh_config "ClientAliveInterval" "0")
    if is_numeric "$alive_interval" && [[ $alive_interval -gt 0 ]] && [[ $alive_interval -le 300 ]]; then
        ((score++)) || true
    else
        issues+=("No idle timeout (ClientAliveInterval=${alive_interval:-0}; should be 1-300)")
    fi

    # PermitEmptyPasswords must be no
    local permit_empty
    permit_empty=$(get_ssh_config "PermitEmptyPasswords" "no")
    if [[ "$permit_empty" == "no" ]]; then
        ((score++)) || true
    else
        issues+=("PermitEmptyPasswords is enabled")
    fi

    # AllowUsers or AllowGroups restricts which accounts can SSH
    local allow_users allow_groups
    allow_users=$(get_ssh_config "AllowUsers" "")
    allow_groups=$(get_ssh_config "AllowGroups" "")
    if [[ -n "$allow_users" ]] || [[ -n "$allow_groups" ]]; then
        ((score++)) || true
    else
        issues+=("No AllowUsers/AllowGroups restriction (all accounts can SSH)")
    fi

    # Explicit Ciphers config: flag known-weak algorithms
    # (absent config means modern OpenSSH defaults, which are acceptable)
    local ciphers_config
    ciphers_config=$(get_ssh_config "Ciphers" "")
    if [[ -n "$ciphers_config" ]]; then
        local found_weak=false
        local weak_cipher
        for weak_cipher in arcfour 3des-cbc blowfish-cbc cast128-cbc \
                           aes128-cbc aes192-cbc aes256-cbc; do
            if [[ "$ciphers_config" == *"$weak_cipher"* ]]; then
                found_weak=true
                break
            fi
        done
        if [[ "$found_weak" == "false" ]]; then
            ((score++)) || true
        else
            issues+=("Weak cipher in Ciphers list: $ciphers_config")
        fi
    else
        ((score++)) || true  # Default ciphers in modern OpenSSH are strong
    fi

    # PubkeyAuthentication should be enabled
    local pubkey_auth
    pubkey_auth=$(get_ssh_config "PubkeyAuthentication" "yes")
    if [[ "$pubkey_auth" == "yes" ]]; then
        ((score++)) || true
    else
        issues+=("PubkeyAuthentication is disabled")
    fi

    if [[ $score -eq $max_score ]]; then
        check_security "SSH Hardening" "PASS" "SSH fully hardened ($score/$max_score settings correct)" ""
    elif [[ $score -ge $((max_score * 2 / 3)) ]]; then
        check_security "SSH Hardening" "WARN" "SSH partially hardened ($score/$max_score): ${issues[*]}" \
            "Harden /etc/ssh/sshd_config: ${issues[0]}"
    else
        check_security "SSH Hardening" "FAIL" "SSH poorly hardened ($score/$max_score correct)" \
            "Disable X11Forwarding, set MaxAuthTries≤3, ClientAliveInterval≤300, restrict AllowUsers"
    fi
}

# Sudoers Security Check
# Covers: NOPASSWD entries in /etc/sudoers and /etc/sudoers.d/*,
#         overly-permissive sudoers file permissions
check_sudoers_security() {
    should_run_check "sudo" || return 0

    local issues=()

    # Scan /etc/sudoers for NOPASSWD
    if [[ -r /etc/sudoers ]]; then
        local nopasswd_count
        nopasswd_count=$(grep -v "^[[:space:]]*#" /etc/sudoers 2>/dev/null | grep -c "NOPASSWD" || echo 0)
        if [[ $nopasswd_count -gt 0 ]]; then
            local nopasswd_entries
            nopasswd_entries=$(grep -v "^[[:space:]]*#" /etc/sudoers 2>/dev/null | \
                               grep "NOPASSWD" | awk '{print $1}' | tr '\n' ' ')
            issues+=("NOPASSWD in /etc/sudoers ($nopasswd_count entries, users: $nopasswd_entries)")
        fi
    fi

    # Scan /etc/sudoers.d/* for NOPASSWD
    if [[ -d /etc/sudoers.d ]]; then
        while IFS= read -r sudoers_file; do
            [[ -r "$sudoers_file" ]] || continue
            local file_nopasswd
            file_nopasswd=$(grep -v "^[[:space:]]*#" "$sudoers_file" 2>/dev/null | \
                            grep -c "NOPASSWD" || echo 0)
            if [[ $file_nopasswd -gt 0 ]]; then
                issues+=("NOPASSWD in ${sudoers_file##*/} ($file_nopasswd entries)")
            fi
        done < <(find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null)
    fi

    # /etc/sudoers permissions should be 440 (root:root, no write anywhere)
    if [[ -f /etc/sudoers ]]; then
        local sudoers_perms
        sudoers_perms=$(portable_stat mode /etc/sudoers)
        if [[ -n "$sudoers_perms" ]] && \
           [[ "$sudoers_perms" != "440" ]] && [[ "$sudoers_perms" != "400" ]]; then
            issues+=("/etc/sudoers permissions: $sudoers_perms (should be 440)")
        fi
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "Sudoers Security" "PASS" "Sudoers configuration is secure" ""
    else
        check_security "Sudoers Security" "WARN" "Found ${#issues[@]} sudoers issue(s): ${issues[0]}" \
            "Remove NOPASSWD from sudoers unless strictly required; use specific commands only"
    fi
}

# Temporary Filesystem Mount Options Check
# Covers: noexec/nosuid/nodev on /tmp, /dev/shm, /var/tmp
# Without noexec, attackers can drop and execute files in world-writable dirs
check_tmp_mount_options() {
    should_run_check "mounts" || return 0

    local issues=()

    # Each mountpoint maps to the required options
    local mountpoints=("/tmp" "/dev/shm" "/var/tmp")
    local required_opts=("noexec" "nosuid" "nodev")

    for mountpoint in "${mountpoints[@]}"; do
        [[ -d "$mountpoint" ]] || continue

        # Read current mount options from /proc/mounts
        local mount_opts
        mount_opts=$(awk -v mp="$mountpoint" '$2 == mp {print $4}' /proc/mounts 2>/dev/null)

        if [[ -z "$mount_opts" ]]; then
            # Not a separate mount — inherits root filesystem options (no noexec etc.)
            issues+=("$mountpoint: not separately mounted (noexec/nosuid/nodev unenforced)")
            continue
        fi

        for opt in "${required_opts[@]}"; do
            if [[ ",$mount_opts," != *",$opt,"* ]]; then
                issues+=("$mountpoint: missing $opt (current: $mount_opts)")
            fi
        done
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "Temp Mount Options" "PASS" "Temporary filesystems mounted with noexec/nosuid/nodev" ""
    else
        check_security "Temp Mount Options" "WARN" "Found ${#issues[@]} insecure temp mount option(s)" \
            "Add noexec,nosuid,nodev to /tmp, /dev/shm, /var/tmp in /etc/fstab"
    fi
}

# File Integrity Monitoring Check
# Covers: AIDE, Tripwire, samhain, OSSEC/Wazuh presence and freshness
check_file_integrity_monitoring() {
    should_run_check "integrity" || return 0

    local fim_installed=false
    local fim_name=""
    local fim_recent=false

    # AIDE (most common on Debian/Ubuntu/RHEL)
    if command -v aide &>/dev/null || [[ -f /etc/aide.conf ]] || [[ -f /etc/aide/aide.conf ]]; then
        fim_installed=true
        fim_name="AIDE"
        # Check database age: AIDE is useful only when run regularly
        local aide_db=""
        for db_path in /var/lib/aide/aide.db /var/lib/aide/aide.db.gz \
                       /var/lib/aide/aide.db.new /var/lib/aide/aide.db.new.gz; do
            [[ -f "$db_path" ]] && { aide_db="$db_path"; break; }
        done
        if [[ -n "$aide_db" ]]; then
            local db_mtime db_age_days
            db_mtime=$(date -r "$aide_db" +%s 2>/dev/null || echo 0)
            db_age_days=$(( ($(date +%s) - db_mtime) / 86400 ))
            [[ $db_age_days -le 7 ]] && fim_recent=true
        fi
    fi

    # Tripwire
    if [[ "$fim_installed" == "false" ]] && \
       { command -v tripwire &>/dev/null || [[ -f /etc/tripwire/tw.cfg ]]; }; then
        fim_installed=true
        fim_name="Tripwire"
        fim_recent=true
    fi

    # samhain
    if [[ "$fim_installed" == "false" ]] && command -v samhain &>/dev/null; then
        fim_installed=true
        fim_name="samhain"
        fim_recent=true
    fi

    # OSSEC / Wazuh (includes FIM)
    if [[ "$fim_installed" == "false" ]] && \
       { command -v ossec-control &>/dev/null || [[ -d /var/ossec ]] || [[ -d /var/wazuh-agent ]]; }; then
        fim_installed=true
        fim_name="OSSEC/Wazuh"
        fim_recent=true
    fi

    if [[ "$fim_installed" == "false" ]]; then
        check_security "File Integrity Monitoring" "WARN" \
            "No file integrity monitoring tool detected" \
            "Install AIDE: apt install aide && aideinit && cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
    elif [[ "$fim_recent" == "false" ]]; then
        check_security "File Integrity Monitoring" "WARN" \
            "$fim_name installed but database not updated in over 7 days" \
            "Schedule 'aide --check' in cron and update the AIDE database regularly"
    else
        check_security "File Integrity Monitoring" "PASS" \
            "File integrity monitoring active and current ($fim_name)" ""
    fi
}

# Rootkit Detection Tools Check
# Covers: rkhunter and chkrootkit installation and recency
check_rootkit_detection() {
    should_run_check "integrity" || return 0

    local rk_installed=false
    local rk_name=""
    local rk_recent=false

    # rkhunter is the most widely deployed rootkit scanner
    if command -v rkhunter &>/dev/null; then
        rk_installed=true
        rk_name="rkhunter"
        # Log recency check (within 7 days)
        local rk_log="/var/log/rkhunter.log"
        if [[ -f "$rk_log" ]]; then
            local log_mtime log_age
            log_mtime=$(date -r "$rk_log" +%s 2>/dev/null || echo 0)
            log_age=$(( ($(date +%s) - log_mtime) / 86400 ))
            [[ $log_age -le 7 ]] && rk_recent=true
        fi
    fi

    # chkrootkit as fallback
    if [[ "$rk_installed" == "false" ]] && command -v chkrootkit &>/dev/null; then
        rk_installed=true
        rk_name="chkrootkit"
        rk_recent=true  # chkrootkit writes no persistent log to check
    fi

    if [[ "$rk_installed" == "false" ]]; then
        check_security "Rootkit Detection" "WARN" \
            "No rootkit scanner installed" \
            "Install rkhunter: apt install rkhunter && rkhunter --propupd && schedule weekly via cron"
    elif [[ "$rk_recent" == "false" ]]; then
        check_security "Rootkit Detection" "WARN" \
            "$rk_name installed but not run in the past 7 days" \
            "Schedule 'rkhunter --check --skip-keypress' weekly via cron"
    else
        check_security "Rootkit Detection" "PASS" \
            "Rootkit scanner present and recently run ($rk_name)" ""
    fi
}

# Legacy / Plaintext Service Check
# Covers: telnet, rsh, rlogin, finger, tftp, talk — all transmit credentials
#         in plaintext and must not be present on a production VPS
check_legacy_services() {
    should_run_check "services" || return 0

    local found_legacy=()

    local legacy_services=(
        telnet telnetd rsh rshd rlogin rlogind rexec rexecd
        finger fingerd tftp tftpd talk talkd ntalkd
    )

    for svc in "${legacy_services[@]}"; do
        if command -v "$svc" &>/dev/null || pkg_installed "$svc"; then
            found_legacy+=("$svc")
        fi
    done

    if [[ ${#found_legacy[@]} -eq 0 ]]; then
        check_security "Legacy Services" "PASS" "No legacy plaintext services found" ""
    elif [[ ${#found_legacy[@]} -le 2 ]]; then
        check_security "Legacy Services" "WARN" \
            "Legacy plaintext service(s) found: ${found_legacy[*]}" \
            "Remove legacy services — they transmit credentials in plaintext"
    else
        check_security "Legacy Services" "FAIL" \
            "Multiple legacy plaintext services present: ${found_legacy[*]}" \
            "Remove all legacy services immediately (telnet/rsh/rlogin/finger/tftp)"
    fi
}

# Sensitive System File Permissions Check
# Covers: /etc/passwd, /etc/shadow, /etc/gshadow, /etc/sudoers, /etc/crontab,
#         /etc/ssh/sshd_config — world-write or unexpected world-read
check_sensitive_permissions() {
    should_run_check "files" || return 0

    local issues=()

    # Files that must never be world-writable
    local no_world_write=(
        /etc/passwd /etc/shadow /etc/group /etc/gshadow
        /etc/sudoers /etc/crontab /etc/hosts /etc/fstab
        /etc/ssh/sshd_config /etc/ssh/ssh_host_rsa_key
        /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ecdsa_key
    )

    for filepath in "${no_world_write[@]}"; do
        [[ -f "$filepath" ]] || continue
        local perms
        perms=$(portable_stat mode "$filepath")
        [[ -z "$perms" ]] && continue
        local world_bit="${perms: -1}"
        if [[ "$world_bit" =~ [2367] ]]; then
            issues+=("$filepath world-writable (perms: $perms)")
        fi
    done

    # /etc/shadow and /etc/gshadow must never be world-readable
    for shadow_file in /etc/shadow /etc/gshadow; do
        [[ -f "$shadow_file" ]] || continue
        local perms
        perms=$(portable_stat mode "$shadow_file")
        [[ -z "$perms" ]] && continue
        local world_bit="${perms: -1}"
        if [[ "$world_bit" =~ [4567] ]]; then
            issues+=("$shadow_file is world-readable (perms: $perms)")
        fi
    done

    # SSH private host keys must be root-readable only (600 or 640)
    for key_file in /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_ed25519_key \
                    /etc/ssh/ssh_host_ecdsa_key; do
        [[ -f "$key_file" ]] || continue
        local perms
        perms=$(portable_stat mode "$key_file")
        [[ -z "$perms" ]] && continue
        # Accept 600 or 640 (some distros use 640 with ssh group)
        if [[ "$perms" != "600" ]] && [[ "$perms" != "640" ]]; then
            issues+=("$key_file: permissions $perms (should be 600 or 640)")
        fi
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "Sensitive File Perms" "PASS" \
            "Critical system files have secure permissions" ""
    else
        check_security "Sensitive File Perms" "FAIL" \
            "Found ${#issues[@]} insecure critical file permission(s): ${issues[0]}" \
            "Fix: chmod 640 /etc/shadow; chmod 440 /etc/sudoers; chmod 600 /etc/ssh/*_key"
    fi
}

# Docker Security Check
# Covers: Docker socket permissions (world-accessible = root equivalent),
#         containers running with --privileged, rootless mode detection
check_docker_security() {
    should_run_check "docker" || return 0

    # Only relevant when Docker is installed
    if ! command -v docker &>/dev/null; then
        return 0
    fi

    local issues=()

    # Docker socket world-accessible is equivalent to passwordless root
    if [[ -S /var/run/docker.sock ]]; then
        local sock_perms sock_uid
        sock_perms=$(portable_stat mode /var/run/docker.sock)
        sock_uid=$(portable_stat uid /var/run/docker.sock)
        if [[ -n "$sock_perms" ]]; then
            local world_bit="${sock_perms: -1}"
            if [[ "$world_bit" =~ [1-7] ]]; then
                issues+=("Docker socket world-accessible (${sock_perms}) — grants root-equivalent access")
            fi
        fi
        if [[ -n "$sock_uid" ]] && [[ "$sock_uid" != "0" ]]; then
            issues+=("Docker socket not owned by root (uid: $sock_uid)")
        fi
    fi

    # Check for --privileged containers (only if daemon is reachable)
    if docker info &>/dev/null 2>&1; then
        local privileged_count=0
        local container_ids
        container_ids=$(docker ps -q 2>/dev/null) || container_ids=""

        if [[ -n "$container_ids" ]]; then
            while IFS= read -r cid; do
                local is_priv
                is_priv=$(docker inspect --format='{{.HostConfig.Privileged}}' "$cid" 2>/dev/null) || is_priv="false"
                if [[ "$is_priv" == "true" ]]; then
                    ((privileged_count++)) || true
                fi
            done <<< "$container_ids"
            if [[ $privileged_count -gt 0 ]]; then
                issues+=("$privileged_count container(s) running with --privileged flag")
            fi
        fi

        # Rootless Docker is a significant security improvement
        if docker info 2>/dev/null | grep -qi "rootless"; then
            check_security "Docker Security" "PASS" "Docker running in rootless mode" ""
            return
        fi

        if [[ ${#issues[@]} -eq 0 ]]; then
            check_security "Docker Security" "PASS" "Docker daemon configured securely" ""
        else
            check_security "Docker Security" "WARN" \
                "Docker security issue(s): ${issues[0]}" \
                "Restrict Docker socket permissions; avoid --privileged containers; consider rootless mode"
        fi
    else
        if [[ ${#issues[@]} -gt 0 ]]; then
            check_security "Docker Security" "WARN" \
                "Docker installed with security concern(s): ${issues[0]}" \
                "Restrict Docker socket permissions"
        else
            check_security "Docker Security" "WARN" \
                "Docker installed but daemon not running" \
                "If Docker is needed, ensure it is configured securely before enabling"
        fi
    fi
}

# Additional Network Sysctl Hardening Check
# Covers settings not included in check_kernel_hardening():
#   ip_forward, source routing, ICMP redirects, sysrq, ptrace_scope
check_network_sysctl() {
    should_run_check "kernel" || return 0

    local score=0
    local max_score=8
    local issues=()

    # Declare as local (not global) to avoid polluting scope
    local -A net_sysctl=(
        ["net.ipv4.ip_forward"]="0"
        ["net.ipv4.conf.all.accept_source_route"]="0"
        ["net.ipv4.conf.all.send_redirects"]="0"
        ["net.ipv4.conf.all.accept_redirects"]="0"
        ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
        ["net.ipv4.icmp_ignore_bogus_error_responses"]="1"
        ["kernel.sysrq"]="0"
        ["kernel.yama.ptrace_scope"]="1"
    )

    for param in "${!net_sysctl[@]}"; do
        local expected="${net_sysctl[$param]}"
        local actual
        actual=$(sysctl -n "$param" 2>/dev/null || echo "")
        if [[ "$actual" == "$expected" ]]; then
            ((score++)) || true
        else
            issues+=("${param}=${actual:-unset} (want ${expected})")
        fi
    done

    if [[ $score -eq $max_score ]]; then
        check_security "Network Sysctl" "PASS" \
            "All network hardening sysctl configured ($score/$max_score)" ""
    elif [[ $score -ge $((max_score / 2)) ]]; then
        check_security "Network Sysctl" "WARN" \
            "Partial network sysctl hardening ($score/$max_score)" \
            "Set in /etc/sysctl.d/99-hardening.conf: ${issues[0]}"
    else
        check_security "Network Sysctl" "FAIL" \
            "Network sysctl hardening insufficient ($score/$max_score)" \
            "Apply all settings: ip_forward=0, accept_source_route=0, sysrq=0, ptrace_scope≥1"
    fi
}

# Home Directory Permissions Check
# World-readable home dirs expose SSH keys, bash history, config files
check_home_directory_permissions() {
    should_run_check "users" || return 0

    local issues=()

    while IFS=: read -r username _ uid _ _ homedir _; do
        # Only check regular user home directories (uid >= 1000)
        [[ $uid -lt 1000 ]] && continue
        [[ -z "$homedir" || ! -d "$homedir" ]] && continue
        # Skip degenerate paths
        [[ "$homedir" == "/" || "$homedir" == "/dev/null" ]] && continue

        local perms
        perms=$(portable_stat mode "$homedir")
        [[ -z "$perms" ]] && continue

        local world_bit="${perms: -1}"
        if [[ "$world_bit" =~ [2367] ]]; then
            issues+=("$homedir ($username) world-writable: $perms")
        elif [[ "$world_bit" =~ [145] ]]; then
            # 5 = r-x, 4 = r--, 1 = --x: all world-readable variants
            issues+=("$homedir ($username) world-readable: $perms")
        fi
    done < /etc/passwd

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "Home Dir Permissions" "PASS" \
            "Home directories have secure permissions" ""
    else
        check_security "Home Dir Permissions" "WARN" \
            "Found ${#issues[@]} home directory with insecure permissions" \
            "Restrict home dirs: chmod 700 /home/<user>"
    fi
}

# NFS Exports Security Check
# no_root_squash, wildcard exports, and 'insecure' allow unauthenticated root access
check_nfs_exports() {
    should_run_check "network" || return 0

    # Only relevant when NFS is configured
    [[ -f /etc/exports ]] || return 0

    local issues=()

    while IFS= read -r line; do
        # Skip comments and blank lines
        [[ "$line" =~ ^[[:space:]]*# || -z "${line// }" ]] && continue

        if [[ "$line" == *"no_root_squash"* ]]; then
            issues+=("no_root_squash: ${line:0:80}")
        fi

        # Wildcard host spec: check each space-separated token after the path
        # token is * alone or *(options) — allows any host to mount
        local has_wildcard=false
        local token
        for token in $line; do
            if [[ "$token" == "*" ]] || [[ "$token" == \*\(* ]]; then
                has_wildcard=true
                break
            fi
        done
        if [[ "$has_wildcard" == "true" ]]; then
            issues+=("wildcard export: ${line:0:80}")
        fi

        if [[ "$line" == *",insecure"* || "$line" == *"(insecure"* ]]; then
            issues+=("insecure option: ${line:0:80}")
        fi
    done < /etc/exports

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "NFS Exports" "PASS" "NFS exports are securely configured" ""
    else
        check_security "NFS Exports" "WARN" \
            "Found ${#issues[@]} insecure NFS export option(s): ${issues[0]}" \
            "Remove no_root_squash, wildcard exports, and 'insecure' from /etc/exports"
    fi
}

# PATH Security Check
# "." in root PATH or world-writable PATH directories allow privilege escalation
check_path_security() {
    should_run_check "system" || return 0

    local issues=()
    local current_path="${PATH:-}"

    IFS=: read -ra path_entries <<< "$current_path"
    for entry in "${path_entries[@]}"; do
        # Empty entry or literal "." both mean "current directory"
        if [[ -z "$entry" || "$entry" == "." ]]; then
            issues+=("PATH contains current directory ('${entry:-empty}') — allows local escalation")
            continue
        fi
        # World-writable directory in PATH
        if [[ -d "$entry" ]]; then
            local perms
            perms=$(portable_stat mode "$entry")
            [[ -z "$perms" ]] && continue
            local world_bit="${perms: -1}"
            if [[ "$world_bit" =~ [2367] ]]; then
                issues+=("World-writable directory in PATH: $entry ($perms)")
            fi
        fi
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "PATH Security" "PASS" "No dangerous entries in root PATH" ""
    else
        check_security "PATH Security" "FAIL" \
            "Dangerous PATH entry: ${issues[0]}" \
            "Remove '.' and world-writable directories from PATH in /etc/environment and /root/.bashrc"
    fi
}

# Exposed Network Services Check
# Databases and caches bound to 0.0.0.0 instead of 127.0.0.1 are a top
# cause of VPS breaches (e.g., MongoDB, Redis, Elasticsearch with no auth)
check_exposed_services() {
    should_run_check "network" || return 0

    local issues=()

    # Map: port -> service name (services that should only listen on loopback)
    local -A local_only_services=(
        ["3306"]="MySQL/MariaDB"
        ["5432"]="PostgreSQL"
        ["6379"]="Redis"
        ["27017"]="MongoDB"
        ["9200"]="Elasticsearch"
        ["9300"]="Elasticsearch cluster"
        ["5672"]="RabbitMQ"
        ["11211"]="Memcached"
        ["8500"]="Consul"
        ["2379"]="etcd"
        ["2380"]="etcd peers"
    )

    # Use ss if available, fall back to netstat
    local listen_output=""
    if command -v ss &>/dev/null; then
        listen_output=$(ss -tuln 2>/dev/null) || listen_output=""
    elif command -v netstat &>/dev/null; then
        listen_output=$(netstat -tuln 2>/dev/null) || listen_output=""
    fi

    [[ -z "$listen_output" ]] && return 0

    for port in "${!local_only_services[@]}"; do
        local svc_name="${local_only_services[$port]}"
        # Check if this port is listening on a non-loopback address
        if echo "$listen_output" | grep -qE "0\.0\.0\.0:${port}[[:space:]]|:::${port}[[:space:]]|\*:${port}[[:space:]]"; then
            # Verify it is actually listening (not just in ss output as a state)
            issues+=("$svc_name (port $port) exposed on all interfaces — should be 127.0.0.1 only")
        fi
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "Exposed Services" "PASS" \
            "No backend services unnecessarily exposed to network" ""
    elif [[ ${#issues[@]} -eq 1 ]]; then
        check_security "Exposed Services" "WARN" \
            "${issues[0]}" \
            "Bind to 127.0.0.1 in the service config and use firewall rules as defence-in-depth"
    else
        check_security "Exposed Services" "FAIL" \
            "${#issues[@]} backend services exposed: ${issues[*]}" \
            "Bind databases/caches to 127.0.0.1 — world-exposed Redis/MongoDB = instant compromise"
    fi
}

# =============================================================================
# SUMMARY AND RECOMMENDATIONS (Issues #69, #70, #71)
# =============================================================================

# Priority order for recommendations
get_priority() {
    local check_name="$1"
    case "$check_name" in
        *"Root Login"*|*"Firewall"*|*"Exposed Services"*|*"Legacy Services"*) echo "1-CRITICAL" ;;
        *"Password Auth"*|*"Updates"*|*"Intrusion"*|*"Sensitive File"*|*"Docker"*) echo "2-HIGH" ;;
        *"SSH"*|*"Port"*|*"SUID"*|*"Kernel"*|*"Network Sysctl"*|*"Sudoers"*) echo "3-MEDIUM" ;;
        *) echo "4-LOW" ;;
    esac
}

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

        # Add assessment for beginners
        if [[ $score -ge 90 ]]; then
            output "${GREEN}Assessment: Excellent - Your server is well hardened${NC}"
        elif [[ $score -ge 70 ]]; then
            output "${YELLOW}Assessment: Good - Minor improvements recommended${NC}"
        elif [[ $score -ge 50 ]]; then
            output "${YELLOW}Assessment: Fair - Several security issues need attention${NC}"
        else
            output "${RED}Assessment: Poor - Critical security issues found, immediate action required${NC}"
        fi
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
        output ""
        output "${GREEN}No security recommendations - your system passed all checks!${NC}"
        return
    fi

    output ""
    output "================================"
    output "${BOLD}Recommended Actions (Priority Order)${NC}"
    output "================================"
    output ""
    output "${GRAY}Fix these issues in order - CRITICAL items first:${NC}"
    output ""

    # Sort recommendations by priority
    local -a critical_recs=()
    local -a high_recs=()
    local -a medium_recs=()
    local -a low_recs=()

    for rec in "${RECOMMENDATIONS[@]}"; do
        local priority
        priority=$(get_priority "$rec")
        case "$priority" in
            1-*) critical_recs+=("$rec") ;;
            2-*) high_recs+=("$rec") ;;
            3-*) medium_recs+=("$rec") ;;
            *) low_recs+=("$rec") ;;
        esac
    done

    local i=1

    # Print CRITICAL
    if [[ ${#critical_recs[@]} -gt 0 ]]; then
        output "${RED}── CRITICAL (Fix Immediately) ──${NC}"
        for rec in "${critical_recs[@]}"; do
            output "${RED}$i.${NC} $rec"
            ((i++))
        done
        output ""
    fi

    # Print HIGH
    if [[ ${#high_recs[@]} -gt 0 ]]; then
        output "${YELLOW}── HIGH PRIORITY ──${NC}"
        for rec in "${high_recs[@]}"; do
            output "${YELLOW}$i.${NC} $rec"
            ((i++))
        done
        output ""
    fi

    # Print MEDIUM
    if [[ ${#medium_recs[@]} -gt 0 ]]; then
        output "${BLUE}── MEDIUM PRIORITY ──${NC}"
        for rec in "${medium_recs[@]}"; do
            output "${BLUE}$i.${NC} $rec"
            ((i++))
        done
        output ""
    fi

    # Print LOW
    if [[ ${#low_recs[@]} -gt 0 ]]; then
        output "${GRAY}── LOW PRIORITY ──${NC}"
        for rec in "${low_recs[@]}"; do
            output "${GRAY}$i.${NC} $rec"
            ((i++))
        done
    fi

    # Write to report
    {
        echo ""
        echo "================================"
        echo "RECOMMENDED ACTIONS (PRIORITY ORDER)"
        echo "================================"
        echo ""
        local j=1

        if [[ ${#critical_recs[@]} -gt 0 ]]; then
            echo "── CRITICAL ──"
            for rec in "${critical_recs[@]}"; do
                echo "$j. $rec"
                ((j++))
            done
            echo ""
        fi

        if [[ ${#high_recs[@]} -gt 0 ]]; then
            echo "── HIGH PRIORITY ──"
            for rec in "${high_recs[@]}"; do
                echo "$j. $rec"
                ((j++))
            done
            echo ""
        fi

        if [[ ${#medium_recs[@]} -gt 0 ]]; then
            echo "── MEDIUM PRIORITY ──"
            for rec in "${medium_recs[@]}"; do
                echo "$j. $rec"
                ((j++))
            done
            echo ""
        fi

        if [[ ${#low_recs[@]} -gt 0 ]]; then
            echo "── LOW PRIORITY ──"
            for rec in "${low_recs[@]}"; do
                echo "$j. $rec"
                ((j++))
            done
        fi
    } >> "$REPORT_FILE"
}

# Print quick-start hardening guide for new VPS
print_quickstart_guide() {
    output ""
    output "================================"
    output "${BOLD}Quick-Start Hardening Guide${NC}"
    output "================================"
    output ""
    output "For a NEW VPS, complete these steps in order:"
    output ""
    output "${BOLD}1. Create a non-root user with sudo access:${NC}"
    output "   adduser yourusername"
    output "   usermod -aG sudo yourusername"
    output ""
    output "${BOLD}2. Set up SSH key authentication:${NC}"
    output "   ssh-copy-id yourusername@your-server-ip"
    output ""
    output "${BOLD}3. Disable root login and password auth:${NC}"
    output "   Edit /etc/ssh/sshd_config:"
    output "   PermitRootLogin no"
    output "   PasswordAuthentication no"
    output "   systemctl restart sshd"
    output ""
    output "${BOLD}4. Enable firewall (only allow SSH):${NC}"
    output "   ufw default deny incoming"
    output "   ufw default allow outgoing"
    output "   ufw allow ssh"
    output "   ufw enable"
    output ""
    output "${BOLD}5. Install and configure fail2ban:${NC}"
    output "   apt install fail2ban"
    output "   systemctl enable fail2ban"
    output ""
    output "${BOLD}6. Enable automatic security updates:${NC}"
    output "   apt install unattended-upgrades"
    output "   dpkg-reconfigure unattended-upgrades"
    output ""
    output "${GRAY}Run this script again after completing these steps.${NC}"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    # Check bash version first
    check_bash_version

    # Parse command line arguments first (before root check for --help)
    parse_args "$@"

    # Initialize colors (after parsing args to respect --quiet)
    init_colors

    # Show guide if requested (before prerequisites since it doesn't need them)
    if [[ "${CONFIG[show_guide]}" == "true" ]]; then
        print_quickstart_guide
        exit 0
    fi

    # Check for dry-run mode (before prerequisites since it doesn't need them)
    if [[ "${CONFIG[dry_run]}" == "true" ]]; then
        output "${BOLD}VPS Security Audit Tool v${VERSION}${NC} (DRY RUN)"
        output "The following checks would be performed:"
        output ""

        local checks=(
            "system:System restart / PATH / boot security checks"
            "ssh:SSH configuration and hardening checks"
            "firewall:Firewall status check"
            "ips:Intrusion prevention check"
            "updates:System updates check"
            "logins:Failed login attempts check"
            "services:Running services and legacy service checks"
            "ports:Open ports check"
            "resources:Resource usage checks"
            "sudo:Sudo logging and sudoers security checks"
            "password:Password policy check"
            "suid:SUID/SGID files scan"
            "mac:SELinux/AppArmor check"
            "kernel:Kernel hardening and network sysctl checks"
            "users:User account and home directory checks"
            "files:File permissions and mount options checks"
            "time:Time synchronization check"
            "audit:Audit system, file integrity, and rootkit checks"
            "core:Core dump settings check"
            "cron:Cron security check"
            "network:Network protocol, IPv6, NFS, and exposed services checks"
            "mounts:Temporary filesystem mount options (noexec/nosuid/nodev)"
            "integrity:File integrity monitoring and rootkit detection"
            "docker:Docker daemon and container security checks"
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

    # Check prerequisites (after colors so we can show warnings)
    check_prerequisites

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
    output "${GRAY}https://github.com/tomtom215/vps-audit${NC}"
    output "${GRAY}Starting audit at $(date)${NC}"
    output ""

    # Write header to report
    {
        echo "VPS Security Audit Tool v${VERSION}"
        echo "https://github.com/tomtom215/vps-audit"
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

    # Additional production hardening checks (Phase 8)
    check_ssh_key_permissions
    check_sgid_files
    check_cron_security
    check_dangerous_protocols
    check_login_banner
    check_account_lockout
    check_umask_settings
    check_log_permissions
    check_secure_boot
    check_process_accounting
    check_ipv6_security
    check_wireless_interfaces
    check_usb_storage
    check_compiler_access

    # Phase 9: Advanced security checks
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

    # Provide helpful hints for new users
    if [[ $CRITICAL_FAIL_COUNT -gt 0 ]]; then
        output ""
        output "${RED}${BOLD}CRITICAL SECURITY ISSUES FOUND!${NC}"
        output "Your server has serious security vulnerabilities that need immediate attention."
        output ""
        output "For step-by-step hardening guidance, run:"
        output "  ${BOLD}sudo $0 --guide${NC}"
    elif [[ $FAIL_COUNT -gt 0 ]]; then
        output ""
        output "${YELLOW}Security issues were found. Review the recommendations above.${NC}"
    fi

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
