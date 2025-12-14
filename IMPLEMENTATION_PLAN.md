# VPS-Audit Complete Refactoring Implementation Plan

## Overview

This document provides a detailed implementation plan for addressing all 78 identified issues in the VPS-Audit script. The plan is organized into 8 phases, prioritized by severity and dependency.

**Estimated Scope:** Complete rewrite with backward-compatible output format

---

## Phase 1: Core Infrastructure & Safety (Issues #1, #2, #3, #9, #21, #22, #42)

### 1.1 Add Bash Safety Options (Issue #1)

**File:** `vps-audit.sh` (Lines 1-2)

**Current:**
```bash
#!/usr/bin/env bash
```

**Implementation:**
```bash
#!/usr/bin/env bash
#
# VPS Security Audit Tool
# Version: 2.0.0
# https://github.com/vernu/vps-audit
#
# Exit on error, undefined variables, and pipeline failures
set -euo pipefail

# Script version for tracking
readonly VERSION="2.0.0"
```

**Notes:**
- `set -e`: Exit on any command failure
- `set -u`: Error on undefined variables
- `set -o pipefail`: Pipeline fails if any command fails
- Add version constant for tracking

---

### 1.2 Root/Sudo Verification (Issue #9)

**Add after safety options:**
```bash
# Verify running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: This script must be run as root or with sudo" >&2
        echo "Usage: sudo $0 [options]" >&2
        exit 1
    fi
}

check_root
```

---

### 1.3 Secure Report File Creation (Issues #2, #3)

**Current:**
```bash
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_FILE="vps-audit-report-${TIMESTAMP}.txt"
```

**Implementation:**
```bash
# Set restrictive umask for all file creation
umask 077

# Create secure temporary report file
create_report_file() {
    local report_dir="${REPORT_DIR:-.}"

    # Verify directory exists and is writable
    if [[ ! -d "$report_dir" ]]; then
        echo "ERROR: Report directory does not exist: $report_dir" >&2
        exit 1
    fi

    if [[ ! -w "$report_dir" ]]; then
        echo "ERROR: Report directory is not writable: $report_dir" >&2
        exit 1
    fi

    # Create file with secure permissions using mktemp
    # mktemp creates file with 600 permissions
    REPORT_FILE=$(mktemp "${report_dir}/vps-audit-report-XXXXXX.txt")

    # Verify file was created
    if [[ ! -f "$REPORT_FILE" ]]; then
        echo "ERROR: Failed to create report file" >&2
        exit 1
    fi

    # Double-check permissions
    chmod 600 "$REPORT_FILE"

    echo "Report file created: $REPORT_FILE"
}
```

---

### 1.4 Cleanup Trap Handler (Issue #21)

**Implementation:**
```bash
# Global state for cleanup
CLEANUP_ON_ERROR=true
REPORT_FILE=""

# Cleanup function
cleanup() {
    local exit_code=$?

    if [[ $exit_code -ne 0 ]] && [[ "$CLEANUP_ON_ERROR" == "true" ]]; then
        if [[ -n "$REPORT_FILE" ]] && [[ -f "$REPORT_FILE" ]]; then
            rm -f "$REPORT_FILE"
            echo "Cleaned up partial report file due to error" >&2
        fi
    fi

    exit $exit_code
}

# Set trap for cleanup
trap cleanup EXIT ERR INT TERM
```

---

### 1.5 Terminal Color Detection (Issue #22)

**Current:**
```bash
GREEN='\033[0;32m'
RED='\033[0;31m'
# ...
```

**Implementation:**
```bash
# Initialize colors based on terminal capability
init_colors() {
    if [[ -t 1 ]] && [[ "${NO_COLOR:-}" != "1" ]]; then
        # Terminal supports colors
        readonly GREEN='\033[0;32m'
        readonly RED='\033[0;31m'
        readonly YELLOW='\033[1;33m'
        readonly GRAY='\033[0;90m'
        readonly BLUE='\033[0;34m'
        readonly BOLD='\033[1m'
        readonly NC='\033[0m'
    else
        # No color support or NO_COLOR environment variable set
        readonly GREEN=''
        readonly RED=''
        readonly YELLOW=''
        readonly GRAY=''
        readonly BLUE=''
        readonly BOLD=''
        readonly NC=''
    fi
}

init_colors
```

---

### 1.6 Exit Code Based on Results (Issue #42)

**Implementation:**
```bash
# Global counters for results
declare -i PASS_COUNT=0
declare -i WARN_COUNT=0
declare -i FAIL_COUNT=0
declare -i CRITICAL_FAIL_COUNT=0

# Modified check_security function
check_security() {
    local test_name="$1"
    local status="$2"
    local message="$3"
    local is_critical="${4:-false}"

    case $status in
        "PASS")
            ((PASS_COUNT++)) || true
            echo -e "${GREEN}[PASS]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[PASS] $test_name - $message" >> "$REPORT_FILE"
            ;;
        "WARN")
            ((WARN_COUNT++)) || true
            echo -e "${YELLOW}[WARN]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[WARN] $test_name - $message" >> "$REPORT_FILE"
            ;;
        "FAIL")
            ((FAIL_COUNT++)) || true
            if [[ "$is_critical" == "true" ]]; then
                ((CRITICAL_FAIL_COUNT++)) || true
            fi
            echo -e "${RED}[FAIL]${NC} $test_name ${GRAY}- $message${NC}"
            echo "[FAIL] $test_name - $message" >> "$REPORT_FILE"
            ;;
        *)
            echo "ERROR: Invalid status '$status' for test '$test_name'" >&2
            ;;
    esac
    echo "" >> "$REPORT_FILE"
}

# Final exit code determination
get_exit_code() {
    if [[ $CRITICAL_FAIL_COUNT -gt 0 ]]; then
        return 2  # Critical failures
    elif [[ $FAIL_COUNT -gt 0 ]]; then
        return 1  # Non-critical failures
    else
        return 0  # All pass or only warnings
    fi
}
```

---

## Phase 2: Command-Line Interface & Configuration (Issues #34, #37, #39, #75, #76)

### 2.1 Command-Line Argument Parsing (Issue #34)

**Implementation:**
```bash
# Default configuration
declare -A CONFIG=(
    [output_dir]="."
    [output_format]="text"
    [verbosity]="normal"
    [skip_network]="false"
    [skip_suid_scan]="false"
    [checks]="all"
    [quiet]="false"
    [json_output]="false"
)

# Threshold configuration (Issue #37)
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

# Usage information
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
                            (ssh,firewall,ips,updates,services,ports,
                             resources,users,suid,kernel,audit)
    --dry-run               Show what checks would run without executing

Threshold Options:
    --disk-warn PCT         Disk usage warning threshold (default: 50)
    --disk-fail PCT         Disk usage failure threshold (default: 80)
    --mem-warn PCT          Memory usage warning threshold (default: 50)
    --mem-fail PCT          Memory usage failure threshold (default: 80)
    --login-warn NUM        Failed login warning threshold (default: 10)
    --login-fail NUM        Failed login failure threshold (default: 50)

Configuration File:
    Place a config file at /etc/vps-audit.conf or ~/.vps-audit.conf

Examples:
    sudo $0                         # Run all checks
    sudo $0 -q -f json              # Quiet mode with JSON output
    sudo $0 --checks ssh,firewall   # Run only SSH and firewall checks
    sudo $0 --no-suid --no-network  # Skip slow/network checks

Report bugs to: https://github.com/vernu/vps-audit/issues
EOF
}

# Parse command line arguments
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
                CONFIG[output_dir]="$2"
                shift
                ;;
            -f|--format)
                CONFIG[output_format]="$2"
                shift
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
                CONFIG[checks]="$2"
                shift
                ;;
            --dry-run)
                CONFIG[dry_run]="true"
                ;;
            --disk-warn)
                THRESHOLDS[disk_warn]="$2"
                shift
                ;;
            --disk-fail)
                THRESHOLDS[disk_fail]="$2"
                shift
                ;;
            --mem-warn)
                THRESHOLDS[mem_warn]="$2"
                shift
                ;;
            --mem-fail)
                THRESHOLDS[mem_fail]="$2"
                shift
                ;;
            --login-warn)
                THRESHOLDS[failed_logins_warn]="$2"
                shift
                ;;
            --login-fail)
                THRESHOLDS[failed_logins_fail]="$2"
                shift
                ;;
            *)
                echo "Unknown option: $1" >&2
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
        if [[ -f "$config_file" ]]; then
            log_verbose "Loading config from: $config_file"
            # shellcheck source=/dev/null
            source "$config_file"
        fi
    done
}
```

---

### 2.2 Logging System (Issue #39)

**Implementation:**
```bash
# Logging functions
log_debug() {
    if [[ "${CONFIG[verbosity]}" == "verbose" ]]; then
        echo -e "${GRAY}[DEBUG] $*${NC}" >&2
    fi
}

log_verbose() {
    if [[ "${CONFIG[verbosity]}" != "quiet" ]]; then
        echo -e "${GRAY}[INFO] $*${NC}"
    fi
}

log_error() {
    echo -e "${RED}[ERROR] $*${NC}" >&2
    echo "[ERROR] $*" >> "$REPORT_FILE"
}

log_warning() {
    echo -e "${YELLOW}[WARNING] $*${NC}" >&2
}

# Quiet mode wrapper
output() {
    if [[ "${CONFIG[quiet]}" != "true" ]]; then
        echo -e "$@"
    fi
}
```

---

### 2.3 Dry-Run Mode (Issue #76)

**Implementation:**
```bash
# Check if should run
should_run_check() {
    local check_name="$1"

    # Check if dry-run mode
    if [[ "${CONFIG[dry_run]:-false}" == "true" ]]; then
        echo "[DRY-RUN] Would run check: $check_name"
        return 1
    fi

    # Check if specific checks requested
    if [[ "${CONFIG[checks]}" != "all" ]]; then
        if [[ ! ",${CONFIG[checks]}," =~ ,$check_name, ]]; then
            log_debug "Skipping check (not in list): $check_name"
            return 1
        fi
    fi

    return 0
}
```

---

## Phase 3: OS Detection & Portability (Issues #14, #15, #26, #64, #65, #66, #67, #68)

### 3.1 OS Detection System

**Implementation:**
```bash
# OS detection and compatibility layer
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

detect_os() {
    # Read os-release
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        OS_INFO[id]="${ID:-unknown}"
        OS_INFO[id_like]="${ID_LIKE:-}"
        OS_INFO[version]="${VERSION_ID:-}"
        OS_INFO[name]="${PRETTY_NAME:-Unknown OS}"
    elif [[ -f /etc/redhat-release ]]; then
        OS_INFO[id]="rhel"
        OS_INFO[name]=$(cat /etc/redhat-release)
    else
        OS_INFO[id]="unknown"
        OS_INFO[name]="Unknown OS"
    fi

    # Determine OS family
    case "${OS_INFO[id]}" in
        ubuntu|debian|linuxmint|pop|elementary|kali|raspbian)
            OS_INFO[family]="debian"
            OS_INFO[pkg_manager]="apt"
            OS_INFO[auth_log]="/var/log/auth.log"
            ;;
        rhel|centos|fedora|rocky|alma|ol|scientific)
            OS_INFO[family]="rhel"
            OS_INFO[pkg_manager]="dnf"
            # Fallback to yum for older systems
            if ! command -v dnf &>/dev/null; then
                OS_INFO[pkg_manager]="yum"
            fi
            OS_INFO[auth_log]="/var/log/secure"
            ;;
        arch|manjaro|endeavouros)
            OS_INFO[family]="arch"
            OS_INFO[pkg_manager]="pacman"
            OS_INFO[auth_log]="/var/log/auth.log"
            ;;
        opensuse*|sles)
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
    if command -v systemctl &>/dev/null && systemctl --version &>/dev/null; then
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
```

---

### 3.2 Package Manager Abstraction (Issues #14, #15)

**Implementation:**
```bash
# Check if package is installed
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
            log_warning "Unknown package manager, cannot check package: $package"
            return 1
            ;;
    esac
}

# Get available updates count
get_update_count() {
    local count=0

    case "${OS_INFO[pkg_manager]}" in
        apt)
            # Run apt update first if cache is old
            local apt_cache="/var/lib/apt/periodic/update-success-stamp"
            if [[ -f "$apt_cache" ]]; then
                local cache_age=$(($(date +%s) - $(stat -c %Y "$apt_cache")))
                if [[ $cache_age -gt 86400 ]]; then
                    log_verbose "APT cache is stale, running update..."
                    apt-get update -qq 2>/dev/null || true
                fi
            fi
            count=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst " || echo 0)
            ;;
        dnf)
            count=$(dnf check-update -q 2>/dev/null | grep -c "^[a-zA-Z]" || echo 0)
            ;;
        yum)
            count=$(yum check-update -q 2>/dev/null | grep -c "^[a-zA-Z]" || echo 0)
            ;;
        pacman)
            # Sync database first
            pacman -Sy &>/dev/null || true
            count=$(pacman -Qu 2>/dev/null | wc -l || echo 0)
            ;;
        zypper)
            count=$(zypper -q lu 2>/dev/null | grep -c "^v" || echo 0)
            ;;
        apk)
            apk update &>/dev/null || true
            count=$(apk version -l '<' 2>/dev/null | wc -l || echo 0)
            ;;
        *)
            log_warning "Cannot check updates for unknown package manager"
            return 1
            ;;
    esac

    echo "$count"
}

# Get security updates count (more specific)
get_security_update_count() {
    local count=0

    case "${OS_INFO[pkg_manager]}" in
        apt)
            # Check specifically for security updates
            count=$(apt-get -s upgrade 2>/dev/null | grep -i security | grep -c "^Inst " || echo 0)
            ;;
        dnf)
            count=$(dnf updateinfo list security 2>/dev/null | grep -c "^" || echo 0)
            ;;
        yum)
            count=$(yum updateinfo list security 2>/dev/null | grep -c "^" || echo 0)
            ;;
        *)
            # Fall back to total updates
            count=$(get_update_count)
            ;;
    esac

    echo "$count"
}
```

---

### 3.3 Service Manager Abstraction (Issue #66)

**Implementation:**
```bash
# Check if service is active
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
            log_warning "Unknown service manager, cannot check service: $service"
            return 1
            ;;
    esac
}

# Get running services count
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
            count=$(service --status-all 2>/dev/null | grep -c "+" || echo 0)
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
```

---

### 3.4 Auth Log Detection (Issues #26, #68)

**Implementation:**
```bash
# Get failed login count
get_failed_logins() {
    local count=0
    local since="${1:-1 day ago}"

    # Try journalctl first (most reliable on systemd)
    if [[ "${OS_INFO[service_manager]}" == "systemd" ]]; then
        count=$(journalctl -u sshd -u ssh --since "$since" 2>/dev/null | \
                grep -c "Failed password" || echo 0)
        if [[ $count -gt 0 ]]; then
            echo "$count"
            return 0
        fi
    fi

    # Fall back to log files
    local log_file="${OS_INFO[auth_log]}"

    # Try multiple possible locations
    local possible_logs=(
        "/var/log/auth.log"
        "/var/log/secure"
        "/var/log/messages"
    )

    for log in "${possible_logs[@]}"; do
        if [[ -f "$log" ]] && [[ -r "$log" ]]; then
            log_file="$log"
            break
        fi
    done

    if [[ -n "$log_file" ]] && [[ -f "$log_file" ]]; then
        # Get today's date pattern for filtering
        local date_pattern
        date_pattern=$(date +"%b %e")

        count=$(grep "$date_pattern" "$log_file" 2>/dev/null | \
                grep -c "Failed password" || echo 0)
    else
        log_warning "No readable auth log found"
        return 1
    fi

    echo "$count"
}
```

---

### 3.5 Portable Command Wrappers (Issue #67)

**Implementation:**
```bash
# Portable uptime
get_uptime() {
    if uptime -p &>/dev/null; then
        uptime -p
    else
        # Fallback for systems without -p flag
        local uptime_seconds
        uptime_seconds=$(cat /proc/uptime 2>/dev/null | cut -d. -f1)
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
    if uptime -s &>/dev/null; then
        uptime -s
    else
        # Calculate from /proc/uptime
        local uptime_seconds
        uptime_seconds=$(cat /proc/uptime 2>/dev/null | cut -d. -f1)
        if [[ -n "$uptime_seconds" ]]; then
            date -d "@$(($(date +%s) - uptime_seconds))" "+%Y-%m-%d %H:%M:%S"
        else
            echo "unknown"
        fi
    fi
}

# Portable memory info
get_memory_info() {
    local field="$1"  # total, used, free, available

    if free --version &>/dev/null 2>&1; then
        # GNU free
        case "$field" in
            total) free -b | awk '/^Mem:/ {print $2}' ;;
            used) free -b | awk '/^Mem:/ {print $3}' ;;
            free) free -b | awk '/^Mem:/ {print $4}' ;;
            available) free -b | awk '/^Mem:/ {print $7}' 2>/dev/null || \
                       free -b | awk '/^Mem:/ {print $4 + $6}' ;;
        esac
    else
        # Fallback to /proc/meminfo
        case "$field" in
            total) grep MemTotal /proc/meminfo | awk '{print $2 * 1024}' ;;
            used)
                local total free buffers cached
                total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
                free=$(grep MemFree /proc/meminfo | awk '{print $2}')
                buffers=$(grep Buffers /proc/meminfo | awk '{print $2}')
                cached=$(grep "^Cached:" /proc/meminfo | awk '{print $2}')
                echo $(((total - free - buffers - cached) * 1024))
                ;;
            free) grep MemFree /proc/meminfo | awk '{print $2 * 1024}' ;;
            available) grep MemAvailable /proc/meminfo | awk '{print $2 * 1024}' 2>/dev/null || \
                      grep MemFree /proc/meminfo | awk '{print $2 * 1024}' ;;
        esac
    fi
}

# Human readable size
human_readable() {
    local bytes="$1"
    if [[ $bytes -lt 1024 ]]; then
        echo "${bytes}B"
    elif [[ $bytes -lt $((1024*1024)) ]]; then
        echo "$((bytes/1024))K"
    elif [[ $bytes -lt $((1024*1024*1024)) ]]; then
        echo "$((bytes/1024/1024))M"
    else
        echo "$((bytes/1024/1024/1024))G"
    fi
}
```

---

## Phase 4: Input Validation & Error Handling (Issues #6, #10, #11, #12, #13, #43, #44, #45)

### 4.1 Numeric Validation (Issues #6, #13)

**Implementation:**
```bash
# Validate numeric value
is_numeric() {
    local value="$1"
    [[ "$value" =~ ^[0-9]+$ ]]
}

# Safe numeric comparison
safe_compare() {
    local value="$1"
    local operator="$2"
    local threshold="$3"

    # Validate inputs
    if ! is_numeric "$value" || ! is_numeric "$threshold"; then
        log_error "Invalid numeric comparison: $value $operator $threshold"
        return 1
    fi

    case "$operator" in
        -lt) [[ $value -lt $threshold ]] ;;
        -le) [[ $value -le $threshold ]] ;;
        -gt) [[ $value -gt $threshold ]] ;;
        -ge) [[ $value -ge $threshold ]] ;;
        -eq) [[ $value -eq $threshold ]] ;;
        -ne) [[ $value -ne $threshold ]] ;;
        *)
            log_error "Invalid operator: $operator"
            return 1
            ;;
    esac
}

# Get SSH port with validation
get_ssh_port() {
    local ssh_port=""
    local config_files=("/etc/ssh/sshd_config")

    # Check for Include directive
    local includes
    includes=$(grep "^Include" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')

    if [[ -n "$includes" ]]; then
        # Expand glob pattern safely
        local expanded_includes
        # shellcheck disable=SC2086
        expanded_includes=$(ls -1 $includes 2>/dev/null || true)
        while IFS= read -r file; do
            [[ -f "$file" ]] && config_files+=("$file")
        done <<< "$expanded_includes"
    fi

    # Search through config files
    for config in "${config_files[@]}"; do
        if [[ -f "$config" ]]; then
            local port
            port=$(grep "^Port " "$config" 2>/dev/null | head -1 | awk '{print $2}')
            if [[ -n "$port" ]]; then
                ssh_port="$port"
                break
            fi
        fi
    done

    # Default to 22 if not specified
    ssh_port="${ssh_port:-22}"

    # Validate it's numeric
    if ! is_numeric "$ssh_port"; then
        log_warning "Invalid SSH port found: $ssh_port, defaulting to 22"
        ssh_port="22"
    fi

    echo "$ssh_port"
}
```

---

### 4.2 Function Input Validation (Issue #44)

**Implementation:**
```bash
# Validated print_info function
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

# Validated check_security function
check_security() {
    local test_name="${1:-}"
    local status="${2:-}"
    local message="${3:-}"
    local is_critical="${4:-false}"

    # Validate required parameters
    if [[ -z "$test_name" ]] || [[ -z "$status" ]] || [[ -z "$message" ]]; then
        log_error "check_security called with missing parameters"
        log_error "  test_name='$test_name' status='$status' message='$message'"
        return 1
    fi

    # Validate status value
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
            [[ "$is_critical" == "true" ]] && ((CRITICAL_FAIL_COUNT++)) || true
            output "${RED}[FAIL]${NC} $test_name ${GRAY}- $message${NC}"
            ;;
    esac

    echo "[$status] $test_name - $message" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}
```

---

### 4.3 Consistent Error Handling (Issue #45)

**Implementation:**
```bash
# Safe command execution with error handling
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

# Safe file read
safe_read_file() {
    local file="$1"
    local default="${2:-}"

    if [[ -f "$file" ]] && [[ -r "$file" ]]; then
        cat "$file"
    else
        log_debug "Cannot read file: $file"
        echo "$default"
    fi
}

# Safe grep with default
safe_grep() {
    local pattern="$1"
    local file="$2"
    local default="${3:-}"

    if [[ -f "$file" ]] && [[ -r "$file" ]]; then
        grep "$pattern" "$file" 2>/dev/null || echo "$default"
    else
        echo "$default"
    fi
}
```

---

### 4.4 Remove Redundant Code (Issues #11, #12)

**Current Issue (Line 46):**
```bash
HOSTNAME=$HOSTNAME
```

**Fix:** Remove the line entirely or use:
```bash
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
```

**Current Issue (Lines 97-98):**
```bash
UPTIME=$(uptime -p)       # Duplicate of line 47
UPTIME_SINCE=$(uptime -s) # Duplicate of line 48
```

**Fix:** Use the already-defined variables from the system info section.

---

## Phase 5: Security Check Improvements (Issues #5, #7, #16, #23, #24, #25, #27, #29, #30, #31)

### 5.1 Fixed SSH Configuration Parsing (Issues #5, #23, #24)

**Implementation:**
```bash
# Get SSH configuration value with proper Include handling
get_ssh_config() {
    local setting="$1"
    local default="$2"
    local value=""

    # Build list of config files to check (in order of precedence)
    local config_files=()

    # Check for Include directives
    local include_pattern
    include_pattern=$(grep "^Include" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')

    if [[ -n "$include_pattern" ]]; then
        # Safely expand the glob pattern
        local dir
        dir=$(dirname "$include_pattern")
        local pattern
        pattern=$(basename "$include_pattern")

        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' file; do
                config_files+=("$file")
            done < <(find "$dir" -maxdepth 1 -name "$pattern" -type f -print0 2>/dev/null | sort -z)
        fi
    fi

    # Add main config file last (lowest precedence for most settings)
    config_files+=("/etc/ssh/sshd_config")

    # Search through files for the setting
    for config in "${config_files[@]}"; do
        if [[ -f "$config" ]] && [[ -r "$config" ]]; then
            value=$(grep -i "^${setting}[[:space:]]" "$config" 2>/dev/null | head -1 | awk '{print $2}')
            if [[ -n "$value" ]]; then
                log_debug "Found $setting=$value in $config"
                break
            fi
        fi
    done

    # Return value or default
    echo "${value:-$default}"
}

# Check SSH root login with proper defaults
check_ssh_root_login() {
    # OpenSSH 7.0+ defaults to "prohibit-password"
    # Older versions default to "yes"
    local ssh_version
    ssh_version=$(ssh -V 2>&1 | grep -oP 'OpenSSH_\K[0-9]+\.[0-9]+' || echo "0.0")

    local default_value="yes"
    if [[ "$(echo "$ssh_version >= 7.0" | bc -l 2>/dev/null)" == "1" ]]; then
        default_value="prohibit-password"
    fi

    local ssh_root
    ssh_root=$(get_ssh_config "PermitRootLogin" "$default_value")

    case "$ssh_root" in
        no)
            check_security "SSH Root Login" "PASS" "Root login is disabled"
            ;;
        prohibit-password|without-password)
            check_security "SSH Root Login" "WARN" "Root login allowed with key only (no password)"
            ;;
        forced-commands-only)
            check_security "SSH Root Login" "WARN" "Root login allowed for forced commands only"
            ;;
        yes)
            check_security "SSH Root Login" "FAIL" "Root login is enabled - disable in /etc/ssh/sshd_config" "true"
            ;;
        *)
            check_security "SSH Root Login" "WARN" "Unknown PermitRootLogin value: $ssh_root"
            ;;
    esac
}

# Check SSH password authentication
check_ssh_password_auth() {
    local ssh_password
    ssh_password=$(get_ssh_config "PasswordAuthentication" "yes")

    if [[ "$ssh_password" == "no" ]]; then
        check_security "SSH Password Auth" "PASS" "Password authentication disabled, key-based only"
    else
        check_security "SSH Password Auth" "WARN" "Password authentication enabled - consider key-based auth"
    fi
}
```

---

### 5.2 Fixed Sudoers Check (Issue #7)

**Implementation:**
```bash
check_sudo_logging() {
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
            if grep -q "^Defaults.*logfile" "$sudoers_file" 2>/dev/null; then
                logging_enabled=true
                log_debug "Sudo logging found in: $sudoers_file"
                break
            fi
            # Also check for syslog
            if grep -q "^Defaults.*syslog" "$sudoers_file" 2>/dev/null; then
                logging_enabled=true
                log_debug "Sudo syslog found in: $sudoers_file"
                break
            fi
        fi
    done

    # Also check if sudo logs to journald by default on systemd systems
    if [[ "${OS_INFO[service_manager]}" == "systemd" ]]; then
        # On systemd systems, sudo commands are logged to journal by default
        logging_enabled=true
    fi

    if [[ "$logging_enabled" == "true" ]]; then
        check_security "Sudo Logging" "PASS" "Sudo commands are being logged"
    else
        check_security "Sudo Logging" "WARN" "Sudo logging not explicitly configured"
    fi
}
```

---

### 5.3 Fixed iptables Check (Issue #16)

**Implementation:**
```bash
check_firewall_status() {
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
        # Check for actual rules, not just existence
        local rule_count
        rule_count=$(nft list ruleset 2>/dev/null | grep -c "^[[:space:]]*chain" || echo 0)
        if [[ $rule_count -gt 0 ]]; then
            firewall_active=true
        fi
    fi

    # Check iptables (legacy)
    if [[ "$firewall_active" == "false" ]] && command -v iptables &>/dev/null; then
        firewall_found=true
        firewall_name="iptables"

        # Count actual rules in INPUT chain (excluding the policy line)
        local input_rules
        input_rules=$(iptables -L INPUT -n --line-numbers 2>/dev/null | tail -n +3 | wc -l)

        # Check if there's any rule or if default policy is DROP/REJECT
        local input_policy
        input_policy=$(iptables -L INPUT -n 2>/dev/null | head -1 | grep -oP '\(policy \K[A-Z]+')

        if [[ $input_rules -gt 0 ]] || [[ "$input_policy" == "DROP" ]] || [[ "$input_policy" == "REJECT" ]]; then
            firewall_active=true
        fi
    fi

    # Report results
    if [[ "$firewall_found" == "false" ]]; then
        check_security "Firewall Status" "FAIL" "No firewall tool found - install ufw, firewalld, or configure iptables" "true"
    elif [[ "$firewall_active" == "true" ]]; then
        check_security "Firewall Status ($firewall_name)" "PASS" "$firewall_name is active and protecting the system"
    else
        check_security "Firewall Status ($firewall_name)" "FAIL" "$firewall_name installed but not properly configured" "true"
    fi
}
```

---

### 5.4 Improved SSH Port Check (Issue #25)

**Implementation:**
```bash
check_ssh_port() {
    local ssh_port
    ssh_port=$(get_ssh_port)

    local unprivileged_start
    unprivileged_start=$(sysctl -n net.ipv4.ip_unprivileged_port_start 2>/dev/null || echo 1024)

    if ! is_numeric "$unprivileged_start"; then
        unprivileged_start=1024
    fi

    if [[ "$ssh_port" == "22" ]]; then
        # Note: This is informational, not a security issue
        check_security "SSH Port" "PASS" "Using standard port 22 (change only if you have specific requirements)"
    elif [[ $ssh_port -ge $unprivileged_start ]]; then
        check_security "SSH Port" "WARN" "Using unprivileged port $ssh_port - port below $unprivileged_start recommended"
    elif [[ $ssh_port -lt 1 ]] || [[ $ssh_port -gt 65535 ]]; then
        check_security "SSH Port" "FAIL" "Invalid SSH port configuration: $ssh_port"
    else
        check_security "SSH Port" "PASS" "Using non-standard privileged port $ssh_port"
    fi
}
```

---

### 5.5 Improved Update Check (Issue #27)

**Implementation:**
```bash
check_system_updates() {
    local total_updates
    local security_updates

    total_updates=$(get_update_count)
    security_updates=$(get_security_update_count)

    if ! is_numeric "$total_updates"; then
        check_security "System Updates" "WARN" "Unable to determine update status"
        return
    fi

    if [[ $total_updates -eq 0 ]]; then
        check_security "System Updates" "PASS" "All packages are up to date"
    elif [[ $security_updates -gt 0 ]]; then
        check_security "System Updates" "FAIL" "$security_updates security updates available (${total_updates} total)" "true"
    else
        check_security "System Updates" "WARN" "$total_updates updates available (no security updates identified)"
    fi
}
```

---

### 5.6 Fixed Service Count (Issue #19)

Already addressed in Phase 3 with `get_running_services_count()`.

---

### 5.7 Improved Password Policy Check (Issue #30)

**Implementation:**
```bash
check_password_policy() {
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
            issues+=("minlen < 12")
        fi

        # Check complexity requirements
        local dcredit ucredit lcredit ocredit
        dcredit=$(grep "^dcredit" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
        ucredit=$(grep "^ucredit" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
        lcredit=$(grep "^lcredit" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
        ocredit=$(grep "^ocredit" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')

        # Negative values mean required, positive means credit
        [[ -n "$dcredit" ]] && [[ "$dcredit" -lt 0 ]] && ((policy_score++)) || issues+=("no digit requirement")
        [[ -n "$ucredit" ]] && [[ "$ucredit" -lt 0 ]] && ((policy_score++)) || issues+=("no uppercase requirement")
        [[ -n "$lcredit" ]] && [[ "$lcredit" -lt 0 ]] && ((policy_score++)) || issues+=("no lowercase requirement")
        [[ -n "$ocredit" ]] && [[ "$ocredit" -lt 0 ]] && ((policy_score++)) || issues+=("no special char requirement")
    else
        issues+=("pwquality.conf not found")
    fi

    # Check PAM configuration for password module
    local pam_password="/etc/pam.d/common-password"
    [[ "${OS_INFO[family]}" == "rhel" ]] && pam_password="/etc/pam.d/system-auth"

    if [[ -f "$pam_password" ]]; then
        if grep -q "pam_pwquality.so" "$pam_password" 2>/dev/null || \
           grep -q "pam_cracklib.so" "$pam_password" 2>/dev/null; then
            log_debug "PAM password quality module enabled"
        else
            issues+=("PAM password quality not enforced")
        fi
    fi

    # Report results
    if [[ $policy_score -ge 4 ]]; then
        check_security "Password Policy" "PASS" "Strong password policy enforced (score: $policy_score/$max_score)"
    elif [[ $policy_score -ge 2 ]]; then
        check_security "Password Policy" "WARN" "Moderate password policy (score: $policy_score/$max_score) - ${issues[*]}"
    else
        check_security "Password Policy" "FAIL" "Weak password policy - ${issues[*]}"
    fi
}
```

---

### 5.8 Fixed SUID Check (Issue #31)

**Implementation:**
```bash
check_suid_files() {
    if [[ "${CONFIG[skip_suid_scan]}" == "true" ]]; then
        log_verbose "Skipping SUID scan (--no-suid flag)"
        return
    fi

    output "${GRAY}Scanning for SUID files (this may take a moment)...${NC}"

    # Known safe SUID binaries (expanded list)
    local known_safe_suid=(
        "/usr/bin/sudo"
        "/usr/bin/su"
        "/usr/bin/passwd"
        "/usr/bin/chsh"
        "/usr/bin/chfn"
        "/usr/bin/newgrp"
        "/usr/bin/gpasswd"
        "/usr/bin/mount"
        "/usr/bin/umount"
        "/usr/bin/ping"
        "/usr/bin/ping6"
        "/usr/bin/traceroute6.iputils"
        "/usr/bin/pkexec"
        "/usr/bin/crontab"
        "/usr/bin/at"
        "/usr/bin/expiry"
        "/usr/bin/chage"
        "/usr/bin/wall"
        "/usr/bin/write"
        "/usr/bin/ssh-agent"
        "/usr/bin/staprun"
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
        "/usr/lib/openssh/ssh-keysign"
        "/usr/lib/policykit-1/polkit-agent-helper-1"
        "/usr/libexec/polkit-agent-helper-1"
        "/usr/sbin/pppd"
        "/usr/sbin/unix_chkpwd"
        "/usr/sbin/postdrop"
        "/usr/sbin/postqueue"
        # Compatibility paths
        "/bin/su"
        "/bin/mount"
        "/bin/umount"
        "/bin/ping"
        "/bin/ping6"
        "/sbin/unix_chkpwd"
    )

    # Build exclusion pattern
    local exclude_pattern
    exclude_pattern=$(printf "|%s" "${known_safe_suid[@]}")
    exclude_pattern="(${exclude_pattern:1})$"

    # Find SUID files, excluding known safe ones
    # Use -xdev to stay on same filesystem (avoid network mounts, /proc, etc.)
    local suspicious_suid=()
    while IFS= read -r file; do
        if [[ -n "$file" ]] && ! echo "$file" | grep -qE "$exclude_pattern"; then
            suspicious_suid+=("$file")
        fi
    done < <(find / -xdev -type f -perm -4000 2>/dev/null)

    local suid_count=${#suspicious_suid[@]}

    if [[ $suid_count -eq 0 ]]; then
        check_security "SUID Files" "PASS" "No unexpected SUID files found"
    elif [[ $suid_count -lt 5 ]]; then
        check_security "SUID Files" "WARN" "Found $suid_count SUID files to review: ${suspicious_suid[*]}"
    else
        check_security "SUID Files" "WARN" "Found $suid_count unexpected SUID files - manual review recommended"
        # Log them all to report
        for file in "${suspicious_suid[@]}"; do
            echo "  - $file" >> "$REPORT_FILE"
        done
    fi
}
```

---

## Phase 6: Network & Port Analysis (Issues #4, #8, #19, #20)

### 6.1 Safe External IP Lookup (Issue #4)

**Implementation:**
```bash
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
        "https://checkip.amazonaws.com"
    )

    for service in "${services[@]}"; do
        ip=$(curl -s --max-time 5 --retry 1 "$service" 2>/dev/null | tr -d '[:space:]')

        # Validate IP format (basic check)
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || \
           [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]]; then
            echo "$ip"
            return
        fi
    done

    echo "(unable to determine)"
}
```

---

### 6.2 SUID Scan with Exclusions (Issue #8)

Already addressed in section 5.8 with `-xdev` flag and proper exclusions.

---

### 6.3 Fixed Port Analysis (Issue #20)

**Implementation:**
```bash
check_open_ports() {
    local listening_info=""

    # Get listening ports
    if command -v ss &>/dev/null; then
        listening_info=$(ss -tuln state listening 2>/dev/null)
    elif command -v netstat &>/dev/null; then
        listening_info=$(netstat -tuln 2>/dev/null | grep LISTEN)
    else
        check_security "Port Security" "WARN" "Neither ss nor netstat available"
        return
    fi

    if [[ -z "$listening_info" ]]; then
        check_security "Port Security" "WARN" "Unable to retrieve listening ports"
        return
    fi

    # Parse ports and categorize
    local -A localhost_ports
    local -A public_ports
    local -A all_ports

    while read -r line; do
        # Skip header
        [[ "$line" =~ ^Netid ]] || [[ "$line" =~ ^Proto ]] && continue
        [[ -z "$line" ]] && continue

        local addr port

        # Handle ss output format
        if [[ "$line" =~ \[?([0-9a-fA-F:.*]+)\]?:([0-9]+) ]]; then
            addr="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
        # Handle netstat output format
        elif [[ "$line" =~ ([0-9.]+|\*|::):([0-9]+) ]]; then
            addr="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
        else
            continue
        fi

        all_ports[$port]=1

        # Categorize by binding address
        case "$addr" in
            127.0.0.1|::1|localhost)
                localhost_ports[$port]=1
                ;;
            0.0.0.0|*|::|"")
                public_ports[$port]=1
                ;;
            *)
                # Specific IP - could be public or private
                if [[ "$addr" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
                    localhost_ports[$port]=1  # Private network
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
    local public_list
    public_list=$(echo "${!public_ports[@]}" | tr ' ' ',' | sed 's/,$//')

    # Evaluate security
    if [[ $public_count -lt ${THRESHOLDS[public_ports_warn]} ]] && \
       [[ $total_count -lt ${THRESHOLDS[ports_warn]} ]]; then
        check_security "Port Security" "PASS" \
            "Good configuration - Total: $total_count, Public: $public_count ($public_list), Localhost-only: $localhost_count"
    elif [[ $public_count -lt ${THRESHOLDS[public_ports_fail]} ]] && \
         [[ $total_count -lt ${THRESHOLDS[ports_fail]} ]]; then
        check_security "Port Security" "WARN" \
            "Review recommended - Total: $total_count, Public: $public_count ($public_list), Localhost-only: $localhost_count"
    else
        check_security "Port Security" "FAIL" \
            "High exposure - Total: $total_count, Public: $public_count ($public_list)"
    fi
}
```

---

## Phase 7: New Security Checks (Issues #46-63)

### 7.1 SELinux/AppArmor Check (Issue #46)

**Implementation:**
```bash
check_mac_status() {
    local mac_system=""
    local mac_status=""

    # Check SELinux
    if command -v getenforce &>/dev/null; then
        mac_system="SELinux"
        mac_status=$(getenforce 2>/dev/null || echo "Unknown")

        case "$mac_status" in
            Enforcing)
                check_security "Mandatory Access Control" "PASS" "SELinux is enforcing"
                return
                ;;
            Permissive)
                check_security "Mandatory Access Control" "WARN" "SELinux is in permissive mode"
                return
                ;;
            Disabled)
                check_security "Mandatory Access Control" "WARN" "SELinux is disabled"
                ;;
        esac
    fi

    # Check AppArmor
    if command -v aa-status &>/dev/null; then
        mac_system="AppArmor"
        if aa-status --enabled &>/dev/null; then
            local profiles
            profiles=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}')
            if [[ -n "$profiles" ]] && [[ "$profiles" -gt 0 ]]; then
                check_security "Mandatory Access Control" "PASS" "AppArmor active with $profiles profiles"
                return
            fi
        fi
        check_security "Mandatory Access Control" "WARN" "AppArmor installed but not active"
        return
    fi

    # Neither found
    check_security "Mandatory Access Control" "WARN" "No MAC system (SELinux/AppArmor) detected"
}
```

---

### 7.2 Kernel Hardening Check (Issue #49)

**Implementation:**
```bash
check_kernel_hardening() {
    local hardening_score=0
    local max_score=6
    local issues=()

    # Check key sysctl settings
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
            issues+=("$setting=$actual (expected $expected)")
        fi
    done

    if [[ $hardening_score -eq $max_score ]]; then
        check_security "Kernel Hardening" "PASS" "All kernel hardening settings properly configured"
    elif [[ $hardening_score -ge $((max_score / 2)) ]]; then
        check_security "Kernel Hardening" "WARN" "Partial kernel hardening ($hardening_score/$max_score)"
    else
        check_security "Kernel Hardening" "FAIL" "Weak kernel hardening ($hardening_score/$max_score) - ${issues[*]}"
    fi
}
```

---

### 7.3 User Account Auditing (Issue #50)

**Implementation:**
```bash
check_user_accounts() {
    local issues=()

    # Check for multiple UID 0 accounts
    local uid0_count
    uid0_count=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null | wc -l)
    if [[ $uid0_count -gt 1 ]]; then
        local uid0_users
        uid0_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null | tr '\n' ',' | sed 's/,$//')
        issues+=("Multiple UID 0 accounts: $uid0_users")
    fi

    # Check for users with empty passwords
    local empty_passwords
    empty_passwords=$(awk -F: '($2 == "" || $2 == "!") && $1 != "+" {print $1}' /etc/shadow 2>/dev/null | wc -l)
    if [[ $empty_passwords -gt 0 ]]; then
        issues+=("$empty_passwords accounts with empty/locked passwords")
    fi

    # Check for non-root users with UID < 1000 and login shells
    local system_users_with_shell
    system_users_with_shell=$(awk -F: '$3 < 1000 && $3 != 0 && $7 !~ /nologin|false|sync|shutdown|halt/ {print $1}' /etc/passwd 2>/dev/null | wc -l)
    if [[ $system_users_with_shell -gt 0 ]]; then
        issues+=("$system_users_with_shell system accounts with login shells")
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "User Accounts" "PASS" "No user account issues found"
    else
        check_security "User Accounts" "WARN" "Issues found: ${issues[*]}"
    fi
}
```

---

### 7.4 World-Writable Files Check (Issue #52)

**Implementation:**
```bash
check_world_writable() {
    output "${GRAY}Checking for world-writable files...${NC}"

    # Find world-writable files (excluding /tmp, /var/tmp, /dev)
    local ww_files
    ww_files=$(find / -xdev -type f -perm -0002 \
        ! -path "/tmp/*" \
        ! -path "/var/tmp/*" \
        ! -path "/dev/*" \
        ! -path "/proc/*" \
        ! -path "/sys/*" \
        2>/dev/null | head -20)

    local ww_count
    ww_count=$(echo "$ww_files" | grep -c "^/" || echo 0)

    # Find world-writable directories without sticky bit
    local ww_dirs
    ww_dirs=$(find / -xdev -type d -perm -0002 ! -perm -1000 \
        ! -path "/tmp" \
        ! -path "/var/tmp" \
        2>/dev/null | head -10)

    local ww_dir_count
    ww_dir_count=$(echo "$ww_dirs" | grep -c "^/" || echo 0)

    if [[ $ww_count -eq 0 ]] && [[ $ww_dir_count -eq 0 ]]; then
        check_security "World-Writable" "PASS" "No dangerous world-writable files/directories found"
    else
        local msg="Found "
        [[ $ww_count -gt 0 ]] && msg+="$ww_count world-writable files "
        [[ $ww_dir_count -gt 0 ]] && msg+="$ww_dir_count world-writable directories without sticky bit"
        check_security "World-Writable" "WARN" "$msg"

        # Log details to report
        [[ -n "$ww_files" ]] && echo "World-writable files: $ww_files" >> "$REPORT_FILE"
        [[ -n "$ww_dirs" ]] && echo "World-writable directories: $ww_dirs" >> "$REPORT_FILE"
    fi
}
```

---

### 7.5 SSH Key Auditing (Issue #53)

**Implementation:**
```bash
check_ssh_keys() {
    local issues=()
    local authorized_keys_files=()

    # Find all authorized_keys files
    while IFS= read -r file; do
        authorized_keys_files+=("$file")
    done < <(find /home -name "authorized_keys" -type f 2>/dev/null)

    # Also check root
    [[ -f /root/.ssh/authorized_keys ]] && authorized_keys_files+=("/root/.ssh/authorized_keys")

    for keyfile in "${authorized_keys_files[@]}"; do
        if [[ -r "$keyfile" ]]; then
            # Check for keys without restrictions
            local unrestricted_keys
            unrestricted_keys=$(grep -c "^ssh-" "$keyfile" 2>/dev/null || echo 0)

            # Check for DSA keys (weak)
            local dsa_keys
            dsa_keys=$(grep -c "ssh-dss" "$keyfile" 2>/dev/null || echo 0)

            # Check for short RSA keys
            local weak_rsa=0
            while read -r key; do
                if [[ "$key" =~ ^ssh-rsa ]]; then
                    # Extract key and check length
                    local key_bits
                    key_bits=$(echo "$key" | ssh-keygen -l -f - 2>/dev/null | awk '{print $1}')
                    if is_numeric "$key_bits" && [[ $key_bits -lt 2048 ]]; then
                        ((weak_rsa++)) || true
                    fi
                fi
            done < "$keyfile"

            [[ $dsa_keys -gt 0 ]] && issues+=("$dsa_keys DSA keys in $keyfile")
            [[ $weak_rsa -gt 0 ]] && issues+=("$weak_rsa weak RSA keys in $keyfile")
        fi
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "SSH Keys" "PASS" "No weak SSH keys found"
    else
        check_security "SSH Keys" "WARN" "${issues[*]}"
    fi
}
```

---

### 7.6 Time Synchronization Check (Issue #54)

**Implementation:**
```bash
check_time_sync() {
    local ntp_active=false
    local ntp_service=""

    # Check systemd-timesyncd
    if service_is_active systemd-timesyncd; then
        ntp_active=true
        ntp_service="systemd-timesyncd"
    fi

    # Check chronyd
    if [[ "$ntp_active" == "false" ]] && service_is_active chronyd; then
        ntp_active=true
        ntp_service="chronyd"
    fi

    # Check ntpd
    if [[ "$ntp_active" == "false" ]] && service_is_active ntpd; then
        ntp_active=true
        ntp_service="ntpd"
    fi
    if [[ "$ntp_active" == "false" ]] && service_is_active ntp; then
        ntp_active=true
        ntp_service="ntp"
    fi

    # Check timedatectl status
    if [[ "$ntp_active" == "false" ]] && command -v timedatectl &>/dev/null; then
        if timedatectl show --property=NTP --value 2>/dev/null | grep -q "yes"; then
            ntp_active=true
            ntp_service="timedatectl"
        fi
    fi

    if [[ "$ntp_active" == "true" ]]; then
        check_security "Time Sync" "PASS" "Time synchronization active ($ntp_service)"
    else
        check_security "Time Sync" "WARN" "No time synchronization service detected"
    fi
}
```

---

### 7.7 Audit System Check (Issue #55)

**Implementation:**
```bash
check_audit_system() {
    # Check if auditd is installed and running
    if pkg_installed auditd || pkg_installed audit; then
        if service_is_active auditd; then
            # Check for rules
            local rule_count
            rule_count=$(auditctl -l 2>/dev/null | grep -c "^-" || echo 0)

            if [[ $rule_count -gt 0 ]]; then
                check_security "Audit System" "PASS" "auditd active with $rule_count rules"
            else
                check_security "Audit System" "WARN" "auditd running but no rules configured"
            fi
        else
            check_security "Audit System" "WARN" "auditd installed but not running"
        fi
    else
        check_security "Audit System" "WARN" "Audit daemon (auditd) not installed"
    fi
}
```

---

### 7.8 Docker Security Check (Issue #56)

**Implementation:**
```bash
check_docker_security() {
    if ! command -v docker &>/dev/null; then
        log_debug "Docker not installed, skipping check"
        return
    fi

    if ! service_is_active docker; then
        check_security "Docker Security" "PASS" "Docker installed but not running"
        return
    fi

    local issues=()

    # Check for privileged containers
    local privileged_count
    privileged_count=$(docker ps --format '{{.Names}}' 2>/dev/null | while read -r name; do
        docker inspect --format '{{.HostConfig.Privileged}}' "$name" 2>/dev/null | grep -c true
    done | awk '{sum+=$1} END {print sum+0}')

    [[ $privileged_count -gt 0 ]] && issues+=("$privileged_count privileged containers")

    # Check for containers with host network
    local host_network
    host_network=$(docker ps --format '{{.Names}}' 2>/dev/null | while read -r name; do
        docker inspect --format '{{.HostConfig.NetworkMode}}' "$name" 2>/dev/null | grep -c "host"
    done | awk '{sum+=$1} END {print sum+0}')

    [[ $host_network -gt 0 ]] && issues+=("$host_network containers using host network")

    # Check for containers running as root
    local root_containers
    root_containers=$(docker ps -q 2>/dev/null | while read -r id; do
        docker exec "$id" id -u 2>/dev/null | grep -c "^0$" || echo 0
    done | awk '{sum+=$1} END {print sum+0}')

    [[ $root_containers -gt 0 ]] && issues+=("$root_containers containers running as root")

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "Docker Security" "PASS" "No obvious Docker security issues"
    else
        check_security "Docker Security" "WARN" "${issues[*]}"
    fi
}
```

---

### 7.9 Core Dump Settings Check (Issue #62)

**Implementation:**
```bash
check_core_dumps() {
    local issues=()

    # Check sysctl setting
    local core_pattern
    core_pattern=$(sysctl -n kernel.core_pattern 2>/dev/null || echo "")

    # Check if core dumps are disabled
    local core_limit
    core_limit=$(ulimit -c 2>/dev/null || echo "0")

    # Check /etc/security/limits.conf
    local limits_core
    limits_core=$(grep -E "^\*.*core" /etc/security/limits.conf 2>/dev/null | tail -1 | awk '{print $4}')

    if [[ "$core_limit" == "0" ]] || [[ "$limits_core" == "0" ]]; then
        check_security "Core Dumps" "PASS" "Core dumps are disabled"
    elif [[ "$core_pattern" =~ ^[|/] ]]; then
        # Core dumps sent to program or specific path
        check_security "Core Dumps" "WARN" "Core dumps enabled with pattern: $core_pattern"
    else
        check_security "Core Dumps" "WARN" "Core dumps are enabled - may leak sensitive data"
    fi
}
```

---

## Phase 8: Output & Reporting (Issues #35, #36, #40, #41, #69, #70, #71, #72, #73, #74)

### 8.1 Remove Unused Function (Issue #36)

**Action:** Delete the `format_for_report()` function (lines 321-325) as it's never called.

---

### 8.2 Reorganize Functions (Issue #35)

**Implementation:** Move all function definitions to the top of the script after variable declarations, organized by category:

```bash
# === UTILITY FUNCTIONS ===
# (logging, validation, helpers)

# === OS DETECTION FUNCTIONS ===
# (detect_os, pkg_installed, etc.)

# === OUTPUT FUNCTIONS ===
# (print_header, print_info, check_security)

# === SECURITY CHECK FUNCTIONS ===
# (individual check functions)

# === MAIN EXECUTION ===
# (argument parsing, main logic)
```

---

### 8.3 Remove Duplicate Info Collection (Issue #40)

**Action:** Remove lines 399-408 that duplicate system info already collected. Use the existing variables instead.

---

### 8.4 Progress Indication (Issue #41)

**Implementation:**
```bash
# Progress indicator for long operations
show_progress() {
    local message="$1"
    if [[ "${CONFIG[quiet]}" != "true" ]]; then
        echo -ne "${GRAY}${message}...${NC}\r"
    fi
}

clear_progress() {
    if [[ "${CONFIG[quiet]}" != "true" ]]; then
        echo -ne "\033[2K\r"  # Clear line
    fi
}

# Usage in long operations:
show_progress "Scanning for SUID files"
# ... do work ...
clear_progress
```

---

### 8.5 Summary Statistics (Issue #69)

**Implementation:**
```bash
print_summary() {
    local total=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))

    echo ""
    echo "================================"
    echo -e "${BOLD}Audit Summary${NC}"
    echo "================================"
    echo -e "${GREEN}PASS:${NC} $PASS_COUNT"
    echo -e "${YELLOW}WARN:${NC} $WARN_COUNT"
    echo -e "${RED}FAIL:${NC} $FAIL_COUNT"
    echo ""
    echo "Total checks: $total"

    # Calculate score
    if [[ $total -gt 0 ]]; then
        local score=$((PASS_COUNT * 100 / total))
        echo -e "Security Score: ${BOLD}${score}%${NC}"
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
```

---

### 8.6 Recommendations Section (Issue #70)

**Implementation:**
```bash
# Store recommendations
declare -a RECOMMENDATIONS=()

# Modified check_security to add recommendations
check_security_with_rec() {
    local test_name="$1"
    local status="$2"
    local message="$3"
    local recommendation="${4:-}"
    local is_critical="${5:-false}"

    # Call original function
    check_security "$test_name" "$status" "$message" "$is_critical"

    # Store recommendation for failed checks
    if [[ "$status" == "FAIL" ]] && [[ -n "$recommendation" ]]; then
        RECOMMENDATIONS+=("[$test_name] $recommendation")
    fi
}

print_recommendations() {
    if [[ ${#RECOMMENDATIONS[@]} -eq 0 ]]; then
        return
    fi

    echo ""
    echo "================================"
    echo -e "${BOLD}Recommended Actions${NC}"
    echo "================================"

    for rec in "${RECOMMENDATIONS[@]}"; do
        echo -e "${YELLOW}→${NC} $rec"
    done

    # Write to report
    {
        echo ""
        echo "================================"
        echo "RECOMMENDED ACTIONS"
        echo "================================"
        for rec in "${RECOMMENDATIONS[@]}"; do
            echo "→ $rec"
        done
    } >> "$REPORT_FILE"
}
```

---

### 8.7 JSON Output (Issue #72)

**Implementation:**
```bash
# JSON output structure
declare -A JSON_RESULTS=()
JSON_OUTPUT=""

init_json() {
    JSON_OUTPUT='{"version":"'"$VERSION"'","timestamp":"'"$(date -Iseconds)"'","hostname":"'"$(hostname)"'","checks":['
}

add_json_result() {
    local test_name="$1"
    local status="$2"
    local message="$3"

    # Escape JSON strings
    test_name=$(echo "$test_name" | sed 's/"/\\"/g')
    message=$(echo "$message" | sed 's/"/\\"/g')

    local json_entry='{"name":"'"$test_name"'","status":"'"$status"'","message":"'"$message"'"}'

    if [[ -n "${JSON_RESULTS[first]:-}" ]]; then
        JSON_OUTPUT+=",$json_entry"
    else
        JSON_OUTPUT+="$json_entry"
        JSON_RESULTS[first]=1
    fi
}

finalize_json() {
    JSON_OUTPUT+='],"summary":{"pass":'"$PASS_COUNT"',"warn":'"$WARN_COUNT"',"fail":'"$FAIL_COUNT"'}}'

    if [[ "${CONFIG[output_format]}" == "json" ]] || [[ "${CONFIG[output_format]}" == "both" ]]; then
        local json_file="${REPORT_FILE%.txt}.json"
        echo "$JSON_OUTPUT" > "$json_file"
        echo "JSON report saved to: $json_file"
    fi
}

# Modify check_security to also output JSON
# Add this to the check_security function:
#   add_json_result "$test_name" "$status" "$message"
```

---

### 8.8 Severity Prioritization (Issue #71)

**Implementation:**
```bash
# Priority levels
declare -A CHECK_PRIORITY=(
    ["SSH Root Login"]="CRITICAL"
    ["Firewall Status"]="CRITICAL"
    ["System Updates"]="HIGH"
    ["SSH Password Auth"]="HIGH"
    ["Intrusion Prevention"]="HIGH"
    ["SUID Files"]="MEDIUM"
    ["Password Policy"]="MEDIUM"
    ["Sudo Logging"]="LOW"
    ["SSH Port"]="LOW"
)

# Sort and display by priority
print_prioritized_results() {
    echo ""
    echo "================================"
    echo -e "${BOLD}Priority Issues${NC}"
    echo "================================"

    # Display CRITICAL failures first
    # Display HIGH failures
    # Display MEDIUM failures
    # etc.
}
```

---

## Phase 9: Documentation Updates (Issues #77, #78)

### 9.1 Update README.md (Issue #77)

**Updates needed:**
1. Document all firewall types checked (UFW, firewalld, iptables, nftables)
2. Document CrowdSec support alongside Fail2ban
3. Fix "Active Internet Connections" description
4. Add new checks to feature list

---

### 9.2 Document All Dependencies (Issue #78)

**Add to README.md:**

```markdown
## Dependencies

### Required (must be installed):
- `bash` >= 4.0
- `coreutils` (grep, awk, sed, cut, etc.)
- `procps` (for process information)

### Network checks (optional):
- `curl` - For public IP detection
- `ss` or `netstat` - For port scanning

### Security checks:
- `sysctl` - Kernel parameter checking
- `find` - SUID file scanning

### Service management:
- `systemctl` (systemd) OR
- `rc-service` (OpenRC) OR
- `service` (SysV)

### Package management (one of):
- `apt/dpkg` (Debian/Ubuntu)
- `dnf/yum/rpm` (RHEL/CentOS/Fedora)
- `pacman` (Arch)
- `zypper` (openSUSE)
- `apk` (Alpine)

### Optional (for specific checks):
- `docker` - Container security checks
- `ufw` / `firewall-cmd` - Firewall checks
- `auditctl` - Audit system checks
- `aa-status` - AppArmor checks
- `getenforce` - SELinux checks
```

---

## Implementation Order

### Sprint 1: Foundation (Issues #1, #2, #3, #9, #21, #22, #42)
- Add safety options and root check
- Secure file creation
- Terminal detection
- Cleanup handlers

### Sprint 2: CLI & Config (Issues #34, #37, #39, #75, #76)
- Command-line argument parsing
- Configuration file support
- Logging system

### Sprint 3: Portability (Issues #14, #15, #26, #64-68)
- OS detection
- Package manager abstraction
- Service manager abstraction
- Portable commands

### Sprint 4: Validation (Issues #4-13, #43-45)
- Input validation
- Error handling
- Remove duplicate code

### Sprint 5: Security Checks Fix (Issues #16-31)
- Fix all existing check logic
- Improve thresholds
- Better defaults

### Sprint 6: New Checks (Issues #46-63)
- SELinux/AppArmor
- Kernel hardening
- User accounts
- Additional security checks

### Sprint 7: Output (Issues #35, #36, #40, #41, #69-74)
- Summary statistics
- JSON output
- Recommendations
- Progress indication

### Sprint 8: Documentation (Issues #77, #78)
- Update README
- Document dependencies

---

## Testing Plan

1. **Unit Testing:** Test each function in isolation
2. **Integration Testing:** Run on multiple distributions:
   - Ubuntu 20.04, 22.04, 24.04
   - Debian 11, 12
   - CentOS 7, 8, 9
   - Rocky Linux 8, 9
   - Fedora latest
   - Alpine latest
3. **Security Testing:** Verify no new vulnerabilities introduced
4. **Performance Testing:** Ensure acceptable runtime (<60s for full audit)
5. **Regression Testing:** Compare output with original script

---

## Migration Notes

- Maintain backward compatibility for existing users
- Report file format changes should be documented
- Consider version flag to identify new features
