#!/usr/bin/env bash
#
# VPS Security Audit Tool
#
# https://github.com/tomtom215/vps-audit
#
# A read-only security audit for Linux VPS servers: it inspects the system,
# prints PASS/WARN/FAIL results with prioritised fixes, and writes a text
# and/or JSON report. It never changes system configuration.
#
# Distributed as one file on purpose (download, chmod +x, run). The version
# below is the single source of truth; see CHANGELOG.md for release notes.
#

# =============================================================================
# CORE INFRASTRUCTURE & SAFETY
# =============================================================================

# The PATH the caller invoked us with, before we harden our own below. The
# "PATH Security" check inspects this one: it describes the environment the
# operator actually runs commands in, not the one this script rewrote.
ORIGINAL_PATH="${PATH:-}"

# Fail a pipeline if any component fails, so mis-parses surface instead of
# silently yielding empty results. We deliberately do NOT use `set -e`/`set -u`:
# many checks probe for things that legitimately may be absent, and errors are
# handled explicitly at each call site.
set -o pipefail

# Prevent accidental clobbering of existing files via `>` redirection.
set -o noclobber

# Deterministic locale. Every check parses command output (df, free, ss, stat,
# sysctl, journalctl, syslog month names, lscpu "Model name", etc.). Without a
# fixed locale these strings and number formats vary per system, silently
# breaking checks. C locale is byte-oriented, English, and uses '.' as the
# decimal separator - exactly what the parsers below assume.
export LC_ALL=C
export LANG=C

# Predictable word-splitting (defend against a hostile inherited IFS).
IFS=$' \t\n'

# Hardened, absolute-path search order. Running as root, we prepend the standard
# system directories so every tool resolves to a trusted location even if the
# invoking environment has a manipulated PATH. Existing entries are preserved
# afterwards for exotic layouts, but trusted directories always win.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"
export PATH

# Restrictive default file-creation mask for the whole run: any report, JSON, or
# temporary artifact is owner-only from the moment of creation (no race window).
umask 077

# Script version (semantic). Single source of truth: --version, the JSON
# report and the release workflow all read this line. Update CHANGELOG.md too.
readonly VERSION="2.5.0"

# Version of the JSON report layout (bump only on a breaking change to it).
readonly JSON_SCHEMA_VERSION=1

# System paths read by the checks. Plain variables (not environment-overridable
# and not readonly) so the test suite can point them at fixtures after sourcing
# this file; nothing in a normal run changes them.
PASSWD_FILE="/etc/passwd"
SHADOW_FILE="/etc/shadow"
PROC_MOUNTS="/proc/mounts"
APT_LISTS_DIR="/var/lib/apt/lists"
APT_UPDATE_STAMP="/var/lib/apt/periodic/update-success-stamp"
DNF_AUTOMATIC_CONF="/etc/dnf/automatic.conf"
ISSUE_FILE="/etc/issue"
CRON_ALLOW="/etc/cron.allow"
CRON_DENY="/etc/cron.deny"
CRON_ETC_DIRS=(/etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly)
CRON_SPOOL_DIRS=(/var/spool/cron/crontabs /var/spool/cron)
SUDOERS_FILE="/etc/sudoers"
SUDOERS_DIR="/etc/sudoers.d"
SUDOERS_RS="/etc/sudoers-rs"
USB_BUS_DIR="/sys/bus/usb"
MODPROBE_DIR="/etc/modprobe.d"
EFI_DIR="/sys/firmware/efi"
PAM_DIR="/etc/pam.d"
PWQUALITY_CONF="/etc/security/pwquality.conf"
PWQUALITY_CONF_D="/etc/security/pwquality.conf.d"
LOGIN_DEFS="/etc/login.defs"
PROFILE_FILES=(/etc/profile /etc/bash.bashrc /etc/bashrc)
LIMITS_CONF="/etc/security/limits.conf"
LIMITS_D="/etc/security/limits.d"
COREDUMP_CONF="/etc/systemd/coredump.conf"
COREDUMP_CONF_D="/etc/systemd/coredump.conf.d"
SSH_DIR="/etc/ssh"
OS_RELEASE_FILE="/etc/os-release"
BOOT_DIR="/boot"
REBOOT_REQUIRED_FILE="/var/run/reboot-required"
IPV4_CONF_DIR="/proc/sys/net/ipv4/conf"
PROC_IF_INET6="/proc/net/if_inet6"
PROC_IPV6_DISABLE="/proc/sys/net/ipv6/conf/all/disable_ipv6"
UFW_DEFAULTS="/etc/default/ufw"
PROC_UPTIME="/proc/uptime"
PROC_LOADAVG="/proc/loadavg"
SYSTEMD_RUNTIME_DIR="/run/systemd/system"

# Monotonic-ish start time for run duration reporting (traceability).
SCRIPT_START_EPOCH="$(date +%s 2>/dev/null || echo 0)"
readonly SCRIPT_START_EPOCH

# Minimum required Bash version
readonly MIN_BASH_VERSION="4.0"

# Global state
REPORT_FILE=""
CLEANUP_ON_ERROR=true
JSON_OUTPUT=""
INVOCATION_ARGS="" # raw command-line arguments, recorded for the report header
declare -i PASS_COUNT=0
declare -i WARN_COUNT=0
declare -i FAIL_COUNT=0
declare -i CRITICAL_FAIL_COUNT=0
declare -i INFO_COUNT=0       # informational results: shown, never scored
declare -a RECOMMENDATIONS=() # entries are "PRIORITY|[Check name] text"
declare -a PREREQ_NOTES=()    # tool-availability notes, printed after the banner
CURRENT_CATEGORY=""           # category of the check function currently running

# =============================================================================
# CONFIGURATION & THRESHOLDS
# =============================================================================

# Check categories: the single source of truth for --checks validation, --help,
# --dry-run, and the README table (a test keeps them in sync). Format is
# "key|description". A check function opts in with `should_run_check "key"`.
readonly -a CHECK_CATEGORIES=(
    "ssh|SSH configuration, hardening and key permissions"
    "firewall|Host firewall (UFW, firewalld, nftables, iptables)"
    "ips|Intrusion prevention (fail2ban, CrowdSec)"
    "updates|Pending updates and automatic updates"
    "logins|Failed login attempts"
    "services|Running services and legacy plaintext daemons"
    "ports|Open ports"
    "resources|Disk, memory and CPU usage"
    "sudo|sudo logging and sudoers review"
    "password|Password policy and account lockout"
    "suid|SUID/SGID file scan"
    "mac|SELinux / AppArmor"
    "kernel|Kernel and network sysctl hardening, risky protocols"
    "users|User accounts and home directory permissions"
    "files|Sensitive file, log and umask permissions"
    "mounts|Mount options of /tmp, /var/tmp and /dev/shm"
    "time|Time synchronisation"
    "audit|auditd and process accounting"
    "integrity|File-integrity monitoring and rootkit scanners"
    "core|Core dump settings"
    "cron|Cron permissions and access control"
    "network|IPv6, wireless, NFS exports and exposed backend services"
    "docker|Docker daemon and container security"
    "system|Reboot needed, PATH, boot security, banner, compilers"
)

# Print the category keys, one per line.
category_keys() {
    local entry
    for entry in "${CHECK_CATEGORIES[@]}"; do
        printf '%s\n' "${entry%%|*}"
    done
}

# Default configuration
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
    [color]="auto"
)

# Configurable thresholds
declare -A THRESHOLDS=(
    # Resource usage (percent). Memory is "used" excluding reclaimable cache.
    [disk_warn]=80
    [disk_fail]=90
    [mem_warn]=80
    [mem_fail]=90
    # Failed SSH login log entries in the last 24 hours (or today)
    [failed_logins_warn]=10
    [failed_logins_fail]=50
    # Distinct publicly reachable listening ports
    [public_ports_warn]=6
    [public_ports_fail]=11
    # Distinct listening ports in total
    [ports_warn]=15
    [ports_fail]=30
)

# OS Information
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
# TERMINAL, COLOR AND TEXT OUTPUT
# =============================================================================
#
# Output rules (each has a regression test in tests/test_output.sh):
#   - ASCII only. The script forces LC_ALL=C for parsing, and operators reach
#     servers through terminals of every charset (PuTTY defaults, serial
#     consoles), so nothing may depend on UTF-8 being rendered.
#   - Data is never used as a printf/echo format string and never passed through
#     `echo -e`: usernames, paths and config lines come from the audited system
#     and must not be able to inject escape sequences into the operator's
#     terminal. Colour codes are real ESC bytes, so plain `%s` printing works.
#   - Colour only on a terminal, and never when NO_COLOR is set to any
#     non-empty value (https://no-color.org), TERM=dumb, --no-color or --quiet.
#   - When stdout is a terminal, long lines are wrapped on word boundaries with
#     a hanging indent; when it is not (cron, pipes, files), lines are left
#     whole so log tooling can grep them.

# True when stdout is a terminal. A function so tests can override it.
stdout_is_tty() {
    [[ -t 1 ]]
}

init_colors() {
    if stdout_is_tty && [[ -z "${NO_COLOR:-}" ]] && [[ "${TERM:-}" != "dumb" ]] &&
        [[ "${CONFIG[color]}" != "false" ]] && [[ "${CONFIG[quiet]}" != "true" ]]; then
        readonly GREEN=$'\033[0;32m'
        readonly RED=$'\033[0;31m'
        readonly YELLOW=$'\033[1;33m'
        readonly GRAY=$'\033[0;90m'
        readonly BLUE=$'\033[0;34m'
        readonly BOLD=$'\033[1m'
        readonly NC=$'\033[0m'
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

# Width, in columns, that console lines are wrapped to. 0 means "do not wrap"
# (stdout is not a terminal). Prefers the kernel's window size, then terminfo,
# then $COLUMNS, then 80; clamped to a sane range.
TERM_COLS=0
init_term_width() {
    TERM_COLS=0
    stdout_is_tty || return 0
    local cols=""
    if has_command stty; then
        cols=$(stty size <&1 2>/dev/null | awk '{print $2}')
    fi
    if ! is_numeric "$cols" || [[ "$cols" -le 0 ]]; then
        cols=$(tput cols 2>/dev/null)
    fi
    if ! is_numeric "$cols" || [[ "$cols" -le 0 ]]; then
        cols="${COLUMNS:-}"
    fi
    if ! is_numeric "$cols" || [[ "$cols" -le 0 ]]; then
        cols=80
    fi
    [[ "$cols" -lt 40 ]] && cols=40
    [[ "$cols" -gt 200 ]] && cols=200
    TERM_COLS="$cols"
}

# Print SINGULAR when COUNT is 1, otherwise PLURAL. Usage: plural COUNT SINGULAR PLURAL
plural() {
    if [[ "$1" == 1 ]]; then printf '%s' "$2"; else printf '%s' "$3"; fi
}

# Replace control characters (ESC, BEL, CR, ...) with a space so text taken
# from the audited system can never drive the terminal. Prints the result.
printable() {
    local s="$1"
    printf '%s' "${s//[[:cntrl:]]/ }"
}

# Wrap TEXT to WIDTH columns on word boundaries. Continuation lines are
# indented by INDENT spaces and, like the first line, never exceed WIDTH.
# Words longer than the available width are split. WIDTH 0 disables wrapping.
# Usage: wrap_text WIDTH INDENT TEXT
wrap_text() {
    local width="$1" indent="$2" text="$3"
    if [[ "$width" -le 0 ]]; then
        printf '%s\n' "$text"
        return 0
    fi
    local pad=""
    printf -v pad '%*s' "$indent" ''
    local -a words=()
    # -d '' reads to EOF; read -a keeps `*` and friends from being glob-expanded.
    IFS=$' \t\n' read -r -d '' -a words <<<"$text" || true

    # `prefix` is "" on the first line and the indent afterwards; `line` is the
    # text accumulated for the current line (without its prefix).
    local prefix="" line="" word avail=$width
    local cont=$((width - indent))
    [[ $cont -lt 1 ]] && cont=1

    for word in "${words[@]}"; do
        # A word that cannot fit on a line of its own is split across lines.
        while [[ ${#word} -gt $avail ]]; do
            if [[ -n "$line" ]]; then
                printf '%s\n' "$prefix$line"
                line=""
            else
                printf '%s\n' "$prefix${word:0:$avail}"
                word="${word:$avail}"
            fi
            prefix="$pad"
            avail=$cont
        done
        [[ -z "$word" ]] && continue
        if [[ -z "$line" ]]; then
            line="$word"
        elif [[ $((${#line} + 1 + ${#word})) -le $avail ]]; then
            line="$line $word"
        else
            printf '%s\n' "$prefix$line"
            prefix="$pad"
            avail=$cont
            line="$word"
        fi
    done
    [[ -n "$line" ]] && printf '%s\n' "$prefix$line"
    return 0
}

# =============================================================================
# LOGGING
# =============================================================================

# Print "[TAG] message" in COLOR, word-wrapped to the terminal with the
# continuation lines indented under the message. Writes to stdout; callers
# redirect. Usage: notice COLOR TAG MESSAGE
notice() {
    local color="$1" tag="[$2]" line
    while IFS= read -r line; do
        printf '%s\n' "${color}${line}${NC}"
    done < <(wrap_text "$TERM_COLS" $((${#tag} + 1)) "$tag $(printable "$3")")
}

# Print TEXT word-wrapped to the terminal in COLOR, with INDENT spaces on the
# continuation lines. Honours --quiet. Usage: output_wrapped COLOR INDENT TEXT
output_wrapped() {
    local color="$1" indent="$2" line
    [[ "${CONFIG[quiet]}" == "true" ]] && return 0
    while IFS= read -r line; do
        printf '%s\n' "${color}${line}${NC}"
    done < <(wrap_text "$TERM_COLS" "$indent" "$(printable "$3")")
}

log_debug() {
    if [[ "${CONFIG[verbosity]}" == "verbose" ]]; then
        printf '%s\n' "${GRAY}[DEBUG] $(printable "$*")${NC}" >&2
    fi
}

log_verbose() {
    if [[ "${CONFIG[verbosity]}" != "quiet" ]] && [[ "${CONFIG[quiet]}" != "true" ]]; then
        notice "$GRAY" NOTE "$*"
    fi
}

log_error() {
    notice "$RED" ERROR "$*" >&2
    if [[ -n "$REPORT_FILE" ]] && [[ -f "$REPORT_FILE" ]]; then
        printf '[ERROR] %s\n' "$(printable "$*")" >>"$REPORT_FILE"
    fi
}

log_warning() {
    if [[ "${CONFIG[quiet]}" != "true" ]]; then
        notice "$YELLOW" WARNING "$*" >&2
    fi
}

# Print one console line unless --quiet. Callers pass colour variables (real
# ESC bytes) and plain text; the arguments are printed verbatim, joined by
# spaces, and are never interpreted as escapes or format strings.
output() {
    if [[ "${CONFIG[quiet]}" != "true" ]]; then
        printf '%s\n' "$*"
    fi
}

# Progress indicator for long operations. The line is cut to one column less
# than the terminal so the carriage return that follows cannot leave a wrapped
# remainder behind.
show_progress() {
    if [[ "${CONFIG[quiet]}" != "true" ]] && stdout_is_tty; then
        local message
        message="$(printable "$1")..."
        if [[ $TERM_COLS -gt 0 && ${#message} -ge $TERM_COLS ]]; then
            message="${message:0:$((TERM_COLS - 1))}"
        fi
        printf '%s\r' "${GRAY}${message}${NC}"
    fi
}

clear_progress() {
    if [[ "${CONFIG[quiet]}" != "true" ]] && stdout_is_tty; then
        printf '\033[2K\r'
    fi
}

# =============================================================================
# CLEANUP & TRAP HANDLERS
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

# The trap is installed inside main() (not here) so the script can be safely
# sourced by the test harness without registering an exit handler in that shell.

# =============================================================================
# INPUT VALIDATION
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

# Count lines read from stdin and print a clean non-negative integer.
#
# This replaces the fragile `cmd | grep -c pat || echo 0` idiom: `grep -c`
# prints "0" AND exits 1 on zero matches, so `|| echo 0` appended a SECOND "0",
# yielding the two-line string "0\n0" that then failed every is_numeric() check
# (e.g. a fully up-to-date server was reported as "unable to determine updates").
# awk always prints exactly one integer, is unaffected by the exit status of
# upstream pipe stages, and never emits BSD-style leading whitespace.
#
# Usage: count=$(some_command | grep "pattern" | count_lines)
count_lines() {
    awk 'END { print NR + 0 }'
}

# Strip everything but digits from a value and echo a clean base-10 integer
# (empty -> "0"). Defensive normaliser for counts obtained from tools whose
# output width or padding varies by platform (e.g. BSD `wc -l`). The 10#
# prefix forces base-10 so a value like "08" is never misread as octal in the
# arithmetic comparisons that consume it.
sanitize_int() {
    local v="${1//[^0-9]/}"
    echo "$((10#${v:-0}))"
}

# A usable percentage threshold: an integer from 1 to 100.
validate_percentage() {
    local value="$1"
    is_numeric "$value" && [[ $((10#$value)) -ge 1 && $((10#$value)) -le 100 ]]
}

# =============================================================================
# ROOT CHECK
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

    if [[ $bash_major -lt $required_major ]] ||
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
    [stat_type]=""    # "gnu" or "bsd"
    [ss_version]=""   # ss version
    [iptables_nft]="" # "true" if iptables uses nftables backend
    [busybox]=""      # "true" if running in busybox environment
    [coreutils]=""    # "gnu" or "busybox" or "bsd"
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
        if stat --version 2>&1 | grep "GNU\|coreutils" >/dev/null; then
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
        if iptables --version 2>&1 | grep "nf_tables" >/dev/null; then
            TOOL_INFO[iptables_nft]="true"
        else
            TOOL_INFO[iptables_nft]="false"
        fi
    fi

    # Get ss version if available
    if has_command ss; then
        TOOL_INFO[ss_version]=$(ss --version 2>&1 | head -1)
        [[ -n "${TOOL_INFO[ss_version]}" ]] || TOOL_INFO[ss_version]="unknown"
    fi

    log_debug "Tool detection: stat=${TOOL_INFO[stat_type]}, coreutils=${TOOL_INFO[coreutils]}, busybox=${TOOL_INFO[busybox]:-false}"
}

# =============================================================================
# PORTABLE STAT WRAPPER
# =============================================================================

# Portable stat wrapper that works on GNU and BSD systems. It always follows
# symlinks (-L): permission checks care about the file a path leads to, and on
# merged-/usr systems /bin and /sbin are symlinks whose own mode is always 777.
# Usage: portable_stat uid|gid|mode|size|owner|group|mtime FILE
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
                uid) stat -L -c '%u' "$file" 2>/dev/null ;;
                gid) stat -L -c '%g' "$file" 2>/dev/null ;;
                mode) stat -L -c '%a' "$file" 2>/dev/null ;;
                size) stat -L -c '%s' "$file" 2>/dev/null ;;
                owner) stat -L -c '%U' "$file" 2>/dev/null ;;
                group) stat -L -c '%G' "$file" 2>/dev/null ;;
                mtime) stat -L -c '%Y' "$file" 2>/dev/null ;;
            esac
            ;;
        bsd)
            case "$format" in
                uid) stat -L -f '%u' "$file" 2>/dev/null ;;
                gid) stat -L -f '%g' "$file" 2>/dev/null ;;
                mode) stat -L -f '%Lp' "$file" 2>/dev/null ;;
                size) stat -L -f '%z' "$file" 2>/dev/null ;;
                owner) stat -L -f '%Su' "$file" 2>/dev/null ;;
                group) stat -L -f '%Sg' "$file" 2>/dev/null ;;
                mtime) stat -L -f '%m' "$file" 2>/dev/null ;;
            esac
            ;;
        *)
            # Fallback: try GNU first, then BSD
            case "$format" in
                uid) stat -L -c '%u' "$file" 2>/dev/null || stat -L -f '%u' "$file" 2>/dev/null ;;
                gid) stat -L -c '%g' "$file" 2>/dev/null || stat -L -f '%g' "$file" 2>/dev/null ;;
                mode) stat -L -c '%a' "$file" 2>/dev/null || stat -L -f '%Lp' "$file" 2>/dev/null ;;
                size) stat -L -c '%s' "$file" 2>/dev/null || stat -L -f '%z' "$file" 2>/dev/null ;;
                owner) stat -L -c '%U' "$file" 2>/dev/null || stat -L -f '%Su' "$file" 2>/dev/null ;;
                group) stat -L -c '%G' "$file" 2>/dev/null || stat -L -f '%Sg' "$file" 2>/dev/null ;;
                mtime) stat -L -c '%Y' "$file" 2>/dev/null || stat -L -f '%m' "$file" 2>/dev/null ;;
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

    PREREQ_NOTES=("${warnings[@]}")
}

# =============================================================================
# SECURE FILE CREATION
# =============================================================================

create_report_file() {
    local report_dir="${CONFIG[output_dir]}"

    # Reaffirm the restrictive mask (already set globally) right before creation.
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

    # Timestamped, traceable, collision-proof filename. The six trailing X's
    # MUST be the final characters of the template: GNU mktemp tolerates a
    # suffix after them, but BusyBox (Alpine) and BSD mktemp reject it and would
    # abort the entire run. So we mktemp without a suffix, then append ".txt".
    local stamp template tmp_report
    stamp=$(date +%Y%m%d-%H%M%S 2>/dev/null || echo "report")
    template="${report_dir}/vps-audit-report-${stamp}-XXXXXX"
    tmp_report=$(mktemp "$template") || {
        log_error "Failed to create report file in: $report_dir"
        exit 1
    }

    REPORT_FILE="${tmp_report}.txt"
    if ! mv -f "$tmp_report" "$REPORT_FILE" 2>/dev/null; then
        # Rename failed (unusual); fall back to the suffix-less file so the run
        # can still proceed. JSON path derivation handles either form.
        REPORT_FILE="$tmp_report"
    fi

    # Double-check permissions (mktemp already created it 600 under umask 077).
    chmod 600 "$REPORT_FILE" 2>/dev/null || true

    log_debug "Report file created: $REPORT_FILE"
}

# =============================================================================
# OS DETECTION
# =============================================================================

detect_os() {
    # Read os-release - parse instead of source to avoid variable conflicts
    if [[ -f "$OS_RELEASE_FILE" ]]; then
        OS_INFO[id]=$(grep "^ID=" "$OS_RELEASE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown")
        OS_INFO[id_like]=$(grep "^ID_LIKE=" "$OS_RELEASE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "")
        OS_INFO[version]=$(grep "^VERSION_ID=" "$OS_RELEASE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "")
        OS_INFO[name]=$(grep "^PRETTY_NAME=" "$OS_RELEASE_FILE" 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "Unknown OS")
    elif [[ -f /etc/redhat-release ]]; then
        OS_INFO[id]="rhel"
        OS_INFO[name]=$(cat /etc/redhat-release)
    else
        OS_INFO[id]="unknown"
        OS_INFO[name]="Unknown OS"
    fi

    # Determine OS family
    case "${OS_INFO[id]}" in
        ubuntu | debian | linuxmint | pop | elementary | kali | raspbian | zorin)
            OS_INFO[family]="debian"
            OS_INFO[pkg_manager]="apt"
            OS_INFO[auth_log]="/var/log/auth.log"
            ;;
        rhel | centos | fedora | rocky | alma | ol | scientific | amzn)
            OS_INFO[family]="rhel"
            if command -v dnf &>/dev/null; then
                OS_INFO[pkg_manager]="dnf"
            else
                OS_INFO[pkg_manager]="yum"
            fi
            OS_INFO[auth_log]="/var/log/secure"
            ;;
        arch | manjaro | endeavouros | artix)
            OS_INFO[family]="arch"
            OS_INFO[pkg_manager]="pacman"
            OS_INFO[auth_log]="/var/log/auth.log"
            ;;
        opensuse* | sles | suse)
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

    # Detect service manager. systemd counts only when it is actually the
    # running init: containers and WSL ship a working `systemctl --version`
    # without systemd being PID 1, and every query then fails. The runtime
    # directory is the same test sd_booted(3) uses.
    if [[ -d "$SYSTEMD_RUNTIME_DIR" ]] && command -v systemctl &>/dev/null; then
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
# PACKAGE MANAGER ABSTRACTION
# =============================================================================

pkg_installed() {
    local package="$1"

    case "${OS_INFO[pkg_manager]}" in
        apt)
            dpkg -l "$package" 2>/dev/null | grep "^ii" >/dev/null
            ;;
        dnf | yum)
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

# With --no-network the package managers that would refresh repository metadata
# are told to use their cache only (dnf/yum -C, zypper --no-refresh), so the
# flag really does keep the audit off the network. apt and pacman answer from
# local state; apk compares against its local index.
package_cache_only_flags() {
    PKG_OFFLINE_FLAGS=()
    [[ "${CONFIG[skip_network]}" == "true" ]] || return 0
    case "${OS_INFO[pkg_manager]}" in
        dnf | yum) PKG_OFFLINE_FLAGS=(-C) ;;
        zypper) PKG_OFFLINE_FLAGS=(--no-refresh) ;;
    esac
}

# Print the number of available package updates, or return 1 (printing nothing)
# if the count genuinely cannot be determined. The distinction matters: the
# caller reports "unable to determine" only on a real error, never for a
# healthy, fully-patched system. Per-manager exit-code semantics are honoured
# (dnf/yum use 100 for "updates available"; pacman uses 1 for "none").
get_update_count() {
    local out rc
    package_cache_only_flags

    case "${OS_INFO[pkg_manager]}" in
        apt)
            out=$(apt-get -s upgrade 2>/dev/null)
            rc=$?
            [[ $rc -ne 0 ]] && return 1
            printf '%s\n' "$out" | grep -c '^Inst '
            ;;
        dnf)
            # 0 = no updates, 100 = updates available, anything else = error
            out=$(dnf -q "${PKG_OFFLINE_FLAGS[@]}" check-update 2>/dev/null)
            rc=$?
            [[ $rc -ne 0 && $rc -ne 100 ]] && return 1
            printf '%s\n' "$out" | grep -c '^[a-zA-Z0-9]'
            ;;
        yum)
            out=$(yum -q "${PKG_OFFLINE_FLAGS[@]}" check-update 2>/dev/null)
            rc=$?
            [[ $rc -ne 0 && $rc -ne 100 ]] && return 1
            printf '%s\n' "$out" | grep -c '^[a-zA-Z0-9]'
            ;;
        pacman)
            # pacman -Qu exits 1 when there are simply no updates (not an error).
            out=$(pacman -Qu 2>/dev/null) || true
            printf '%s\n' "$out" | grep -c '.'
            ;;
        zypper)
            out=$(zypper -q "${PKG_OFFLINE_FLAGS[@]}" lu 2>/dev/null)
            rc=$?
            [[ $rc -ne 0 ]] && return 1
            printf '%s\n' "$out" | grep -c '^v '
            ;;
        apk)
            out=$(apk version -l '<' 2>/dev/null)
            rc=$?
            [[ $rc -ne 0 ]] && return 1
            # Drop apk's header line, then count remaining entries.
            printf '%s\n' "$out" | grep -v '^Installed' | grep -c '.'
            ;;
        *)
            log_warning "Cannot check updates for unknown package manager"
            return 1
            ;;
    esac
    # grep -c already emits a clean "0" on no matches; its exit status is
    # irrelevant to the count and is intentionally ignored.
    return 0
}

# Count the distinct packages in `dnf/yum updateinfo list` output on stdin. One
# row is printed per advisory and package version, so a package touched by
# several advisories appears several times (a fresh Rocky Linux 9 image lists 58
# rows for 32 packages). Rows are "ADVISORY SEVERITY NAME-[EPOCH:]VERSION-RELEASE.ARCH";
# VERSION and RELEASE never contain a dash, so dropping the last two dash
# fields leaves the package name.
count_security_packages() {
    awk '/^[A-Za-z]/ && NF >= 3 {print $3}' | sed -E 's/-[^-]+-[^-]+$//' | sort -u | grep -c .
}

# The command that installs pending updates with the detected package manager.
upgrade_command() {
    case "${OS_INFO[pkg_manager]}" in
        apt) echo "apt upgrade" ;;
        dnf) echo "dnf upgrade" ;;
        yum) echo "yum update" ;;
        zypper) echo "zypper update" ;;
        pacman) echo "pacman -Syu" ;;
        apk) echo "apk upgrade" ;;
        *) echo "your package manager's upgrade command" ;;
    esac
}

# Print the number of available SECURITY updates. Returns 1 (printing nothing)
# when it cannot be determined for the current package manager.
get_security_update_count() {
    local out rc
    package_cache_only_flags

    case "${OS_INFO[pkg_manager]}" in
        apt)
            out=$(apt-get -s upgrade 2>/dev/null)
            rc=$?
            [[ $rc -ne 0 ]] && return 1
            # Security-origin lines contain the "-security" suite on the Inst line.
            printf '%s\n' "$out" | grep '^Inst ' | grep -c -i 'security'
            ;;
        dnf)
            out=$(dnf -q "${PKG_OFFLINE_FLAGS[@]}" updateinfo list --security --available 2>/dev/null)
            rc=$?
            [[ $rc -ne 0 && $rc -ne 100 ]] && return 1
            count_security_packages <<<"$out"
            ;;
        yum)
            out=$(yum -q "${PKG_OFFLINE_FLAGS[@]}" updateinfo list security 2>/dev/null)
            rc=$?
            [[ $rc -ne 0 && $rc -ne 100 ]] && return 1
            count_security_packages <<<"$out"
            ;;
        *)
            # No reliable per-security query: fall back to the total update count.
            get_update_count
            ;;
    esac
    return 0
}

# =============================================================================
# SERVICE MANAGER ABSTRACTION
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
            sv status "$service" 2>/dev/null | grep "^run:" >/dev/null
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
            local units
            units=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null) || return 1
            count=$(printf '%s\n' "$units" | count_lines)
            ;;
        openrc)
            count=$(rc-status -s 2>/dev/null | grep -c "started" || true)
            ;;
        sysv)
            count=$(service --status-all 2>/dev/null | grep -c " + " || true)
            ;;
        runit)
            count=$(find /var/service -maxdepth 1 -type l 2>/dev/null | count_lines)
            ;;
        *)
            log_warning "Cannot count services for unknown service manager"
            return 1
            ;;
    esac

    echo "$count"
}

# =============================================================================
# PORTABLE COMMAND WRAPPERS
# =============================================================================

# Uptime and load come from /proc, which every Linux has, instead of the
# `uptime` command: it lives in procps, which minimal images (Rocky, Alma,
# openSUSE containers) do not install, and its flags differ between GNU and
# BusyBox.

# "up 2 days, 3 hours, 5 minutes" (units of zero are omitted; "up 0 minutes"
# when under a minute).
get_uptime() {
    local secs
    secs=$(cut -d. -f1 "$PROC_UPTIME" 2>/dev/null)
    is_numeric "$secs" || {
        echo "unknown"
        return 1
    }
    local d=$((secs / 86400)) h=$(((secs % 86400) / 3600)) m=$(((secs % 3600) / 60))
    local -a parts=()
    [[ $d -gt 0 ]] && parts+=("$d day$([[ $d -ne 1 ]] && echo s)")
    [[ $h -gt 0 ]] && parts+=("$h hour$([[ $h -ne 1 ]] && echo s)")
    if [[ $m -gt 0 || ${#parts[@]} -eq 0 ]]; then
        parts+=("$m minute$([[ $m -ne 1 ]] && echo s)")
    fi
    local out="" part
    for part in "${parts[@]}"; do
        out+="${out:+, }$part"
    done
    echo "up $out"
}

get_uptime_since() {
    local secs
    secs=$(cut -d. -f1 "$PROC_UPTIME" 2>/dev/null)
    is_numeric "$secs" || {
        echo "unknown"
        return 1
    }
    date -d "@$(($(date +%s) - secs))" "+%Y-%m-%d %H:%M:%S" 2>/dev/null || echo "unknown"
}

# Load averages as "0.41, 0.68, 0.56", or just the 1-minute figure.
# Usage: get_load_average [all|1min]
get_load_average() {
    local l1 l5 l15 _
    read -r l1 l5 l15 _ <"$PROC_LOADAVG" 2>/dev/null || return 1
    [[ -n "$l1" ]] || return 1
    if [[ "${1:-all}" == "1min" ]]; then
        echo "$l1"
    else
        echo "$l1, $l5, $l15"
    fi
}

# Format a byte count as a compact human-readable string (e.g. "1.9G"),
# mirroring `free -h`. Uses awk for the division so it works without bc and
# under LC_ALL=C (period decimal separator).
bytes_to_human() {
    local bytes="${1:-0}"
    is_numeric "$bytes" || {
        echo "?"
        return
    }
    if [[ $bytes -ge 1073741824 ]]; then
        awk -v b="$bytes" 'BEGIN{printf "%.1fG", b/1073741824}'
    elif [[ $bytes -ge 1048576 ]]; then
        awk -v b="$bytes" 'BEGIN{printf "%.1fM", b/1048576}'
    elif [[ $bytes -ge 1024 ]]; then
        awk -v b="$bytes" 'BEGIN{printf "%.1fK", b/1024}'
    else echo "${bytes}B"; fi
}

get_memory_stats() {
    local stat="$1" # total|used|available|percent|*_human

    # Read straight from /proc/meminfo (present on every Linux system). This
    # avoids depending on `free`, whose -b/-h flags and column layout differ
    # across GNU coreutils and BusyBox (Alpine), which previously left the
    # byte/human values blank there.
    local total_kb avail_kb free_kb buffers_kb cached_kb
    if [[ -r /proc/meminfo ]]; then
        total_kb=$(awk '/^MemTotal:/     {print $2; exit}' /proc/meminfo)
        avail_kb=$(awk '/^MemAvailable:/ {print $2; exit}' /proc/meminfo)
        free_kb=$(awk '/^MemFree:/      {print $2; exit}' /proc/meminfo)
        buffers_kb=$(awk '/^Buffers:/    {print $2; exit}' /proc/meminfo)
        cached_kb=$(awk '/^Cached:/      {print $2; exit}' /proc/meminfo)
    fi

    total_kb=$(sanitize_int "$total_kb")
    # MemAvailable is absent on very old kernels (<3.14): approximate it.
    if ! is_numeric "$avail_kb"; then
        avail_kb=$(($(sanitize_int "$free_kb") + $(sanitize_int "$buffers_kb") + $(sanitize_int "$cached_kb")))
    fi
    avail_kb=$(sanitize_int "$avail_kb")

    local used_kb=$((total_kb - avail_kb))
    [[ $used_kb -lt 0 ]] && used_kb=0

    case "$stat" in
        total) echo $((total_kb * 1024)) ;;
        used) echo $((used_kb * 1024)) ;;
        available) echo $((avail_kb * 1024)) ;;
        percent) if [[ $total_kb -gt 0 ]]; then echo $((used_kb * 100 / total_kb)); else echo 0; fi ;;
        total_human) bytes_to_human $((total_kb * 1024)) ;;
        used_human) bytes_to_human $((used_kb * 1024)) ;;
        available_human) bytes_to_human $((avail_kb * 1024)) ;;
    esac
}

# Print the number of CPU cores, or return 1 (printing nothing) if unknown.
# Prefers nproc (honours cgroup/affinity limits) and falls back to counting
# processor entries in /proc/cpuinfo. Never emits the "0\n1" double-value that
# the previous `nproc || grep -c || echo 1` chain could produce.
get_cpu_cores() {
    local n=""
    if has_command nproc; then
        n=$(nproc 2>/dev/null || true)
    fi
    if ! is_numeric "$n" && [[ -r /proc/cpuinfo ]]; then
        n=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || true)
    fi
    if is_numeric "$n" && [[ $n -gt 0 ]]; then
        echo "$n"
        return 0
    fi
    return 1
}

# Human-friendly elapsed run time since the script started (traceability).
get_run_duration() {
    local now elapsed
    now=$(date +%s 2>/dev/null || echo "$SCRIPT_START_EPOCH")
    elapsed=$((now - SCRIPT_START_EPOCH))
    [[ $elapsed -lt 0 ]] && elapsed=0
    if [[ $elapsed -ge 60 ]]; then
        printf '%dm %ds' $((elapsed / 60)) $((elapsed % 60))
    else
        printf '%ds' "$elapsed"
    fi
}

# =============================================================================
# OUTPUT FUNCTIONS
# =============================================================================

print_header() {
    local header
    header="$(printable "$1")"
    output ""
    output "${BLUE}${BOLD}${header}${NC}"
    {
        printf '\n%s\n' "$header"
        printf '%s\n' "================================"
    } >>"$REPORT_FILE"
}

# Name shown in the report header: the fully qualified name when allowed.
# `hostname -f` resolves the name through DNS when it is not in /etc/hosts, so
# --no-network skips it. It can also BLOCK for the resolver timeout on a VPS
# with broken DNS (the fallback only fires on a non-zero exit, not on a hang),
# so it is bounded with `timeout`.
get_display_hostname() {
    local name=""
    if [[ "${CONFIG[skip_network]}" == "true" ]]; then
        name=$(hostname 2>/dev/null)
    elif has_command timeout; then
        name=$(timeout 2 hostname -f 2>/dev/null || hostname 2>/dev/null)
    else
        name=$(hostname 2>/dev/null)
    fi
    [[ -n "$name" ]] || name="unknown"
    printf '%s' "$name"
}

print_info() {
    local label value
    label="$(printable "${1:-}")"
    value="$(printable "${2:-}")"

    if [[ -z "$label" ]]; then
        log_error "print_info called without label"
        return 1
    fi

    # Value can be empty, but show placeholder
    if [[ -z "$value" ]]; then
        value="(not available)"
    fi

    # Continuation lines are indented 4 columns; the label stays bold.
    local -a lines=()
    local line
    mapfile -t lines < <(wrap_text "$TERM_COLS" 4 "$label: $value")
    if [[ "${lines[0]}" == "$label:"* ]]; then
        output "${BOLD}${label}:${NC}${lines[0]:$((${#label} + 1))}"
    else
        output "${lines[0]}"
    fi
    for line in "${lines[@]:1}"; do
        output "$line"
    done
    printf '%s: %s\n' "$label" "$value" >>"$REPORT_FILE"
}

# Recommendation priority, derived from the verdict itself:
#   1 critical  FAIL flagged critical (fix immediately)
#   2 high      any other FAIL
#   3 medium    WARN
#   4 low       INFO, or a WARN from a defence-in-depth check
# The name is matched exactly, never as a substring, and recommendation text
# plays no part (it used to, and promoted a key-only root login WARN to
# "CRITICAL" while demoting a critical failing update to HIGH).
# Usage: compute_priority STATUS CRITICAL NAME
compute_priority() {
    local status="$1" critical="$2" name="$3"
    if [[ "$status" == "INFO" ]]; then
        echo 4
        return 0
    fi
    if [[ "$status" == "FAIL" ]]; then
        if [[ "$critical" == "true" ]]; then echo 1; else echo 2; fi
        return 0
    fi
    case "$name" in
        "Login Banner" | "Core Dumps" | "Network Protocols" | "SGID Files" | "Cron Security" | \
            "Account Lockout" | "Umask Settings" | "Wireless Interfaces")
            echo 4
            ;;
        *)
            echo 3
            ;;
    esac
}

priority_label() {
    case "$1" in
        1) echo critical ;;
        2) echo high ;;
        3) echo medium ;;
        4) echo low ;;
        *) echo "" ;;
    esac
}

# Print one wrapped, coloured result line:  [STATUS] Name - message
render_result_line() {
    local status="$1" color="$2" name message
    name="$(printable "$3")"
    message="$(printable "$4")"
    local tag="[$status]"
    local head="$tag $name"
    local -a lines=()
    mapfile -t lines < <(wrap_text "$TERM_COLS" $((${#tag} + 1)) "$head - $message")

    local first="${lines[0]}" line
    if [[ "$first" == "$head"* ]]; then
        output "${color}${tag}${NC}${first:${#tag}:$((${#head} - ${#tag}))}${GRAY}${first:${#head}}${NC}"
    else
        output "${color}${tag}${NC}${GRAY}${first:${#tag}}${NC}"
    fi
    for line in "${lines[@]:1}"; do
        output "${GRAY}${line}${NC}"
    done
}

# Record and print one check result.
# Usage: check_security NAME STATUS MESSAGE [RECOMMENDATION] [CRITICAL=true|false]
# STATUS is PASS, WARN, FAIL or INFO. INFO is shown but never scored and never
# changes the exit code: it is for facts that are worth knowing yet are not a
# security failure on a correctly run VPS. CRITICAL only has meaning for FAIL.
check_security() {
    local test_name="${1:-}"
    local status="${2:-}"
    local message="${3:-}"
    local recommendation="${4:-}"
    local is_critical="${5:-false}"

    if [[ -z "$test_name" ]] || [[ -z "$status" ]] || [[ -z "$message" ]]; then
        log_error "check_security called with missing parameters"
        return 1
    fi

    case "$status" in
        PASS | WARN | FAIL | INFO) ;;
        *)
            log_error "Invalid status '$status' for test '$test_name'"
            return 1
            ;;
    esac
    [[ "$status" == "FAIL" ]] || is_critical="false"
    [[ "$is_critical" == "true" ]] || is_critical="false"

    local color
    case "$status" in
        PASS)
            ((PASS_COUNT++)) || true
            color="$GREEN"
            ;;
        WARN)
            ((WARN_COUNT++)) || true
            color="$YELLOW"
            ;;
        FAIL)
            ((FAIL_COUNT++)) || true
            [[ "$is_critical" == "true" ]] && { ((CRITICAL_FAIL_COUNT++)) || true; }
            color="$RED"
            ;;
        INFO)
            ((INFO_COUNT++)) || true
            color="$BLUE"
            ;;
    esac

    render_result_line "$status" "$color" "$test_name" "$message"

    {
        printf '[%s] %s - %s\n' "$status" "$(printable "$test_name")" "$(printable "$message")"
    } >>"$REPORT_FILE"

    # Store the recommendation for non-passing checks.
    local priority=""
    if [[ "$status" != "PASS" ]]; then
        priority="$(compute_priority "$status" "$is_critical" "$test_name")"
        if [[ -n "$recommendation" ]]; then
            RECOMMENDATIONS+=("${priority}|[$test_name] $recommendation")
            printf '  Recommendation: %s\n' "$(printable "$recommendation")" >>"$REPORT_FILE"
        fi
    fi
    echo "" >>"$REPORT_FILE"

    if [[ "${CONFIG[output_format]}" == "json" ]] || [[ "${CONFIG[output_format]}" == "both" ]]; then
        add_json_result "$test_name" "$status" "$message" "$recommendation" "$is_critical" "$priority"
    fi
}

# =============================================================================
# JSON OUTPUT
# =============================================================================

# Escape a string for embedding in a JSON string literal. Backslash must be
# escaped first. Every control character below U+0020 must be escaped
# (RFC 8259 section 7): log lines and config files can contain ESC and BEL, and
# a single raw one makes the whole report unparsable.
json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/\\r}"
    str="${str//$'\t'/\\t}"
    if [[ "$str" == *[[:cntrl:]]* ]]; then
        local i hex ch
        for ((i = 1; i < 32; i++)); do
            printf -v hex '%02x' "$i"
            printf -v ch '%b' "\\x$hex"
            str="${str//"$ch"/\\u00$hex}"
        done
    fi
    printf '%s' "$str"
}

JSON_CHECK_COUNT=0

init_json() {
    local timestamp
    timestamp=$(date -Iseconds 2>/dev/null || date)
    JSON_CHECK_COUNT=0
    JSON_OUTPUT='{"version":"'"$VERSION"'","schema_version":'"$JSON_SCHEMA_VERSION"
    JSON_OUTPUT+=',"timestamp":"'"$(json_escape "$timestamp")"'"'
    JSON_OUTPUT+=',"hostname":"'"$(json_escape "$(hostname 2>/dev/null)")"'"'
    JSON_OUTPUT+=',"os":"'"$(json_escape "${OS_INFO[name]}")"'","checks":['
}

# Usage: add_json_result NAME STATUS MESSAGE RECOMMENDATION CRITICAL PRIORITY
add_json_result() {
    local test_name status message recommendation is_critical="${5:-false}" priority="${6:-}"
    test_name=$(json_escape "$1")
    status="$2"
    message=$(json_escape "$3")
    recommendation=$(json_escape "${4:-}")

    local priority_json="null" label
    label="$(priority_label "$priority")"
    [[ -n "$label" ]] && priority_json="\"$label\""

    local entry
    entry='{"name":"'"$test_name"'","category":"'"$(json_escape "$CURRENT_CATEGORY")"'"'
    entry+=',"status":"'"$status"'","message":"'"$message"'","recommendation":"'"$recommendation"'"'
    entry+=',"critical":'"$is_critical"',"priority":'"$priority_json"'}'

    if [[ $JSON_CHECK_COUNT -gt 0 ]]; then
        JSON_OUTPUT+=","
    fi
    JSON_OUTPUT+="$entry"
    JSON_CHECK_COUNT=$((JSON_CHECK_COUNT + 1))
}

finalize_json() {
    local total=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))
    local score=0
    [[ $total -gt 0 ]] && score=$((PASS_COUNT * 100 / total))
    local now duration_s
    now=$(date +%s 2>/dev/null || echo "$SCRIPT_START_EPOCH")
    duration_s=$((now - SCRIPT_START_EPOCH))
    [[ $duration_s -lt 0 ]] && duration_s=0

    JSON_OUTPUT+='],"summary":{"pass":'"$PASS_COUNT"',"warn":'"$WARN_COUNT"',"fail":'"$FAIL_COUNT"',"info":'"$INFO_COUNT"',"critical_fail":'"$CRITICAL_FAIL_COUNT"',"total":'"$total"',"score":'"$score"',"duration_seconds":'"$duration_s"'}}'

    if [[ "${CONFIG[output_format]}" == "json" ]] || [[ "${CONFIG[output_format]}" == "both" ]]; then
        local json_file="${REPORT_FILE%.txt}.json"
        # >| overrides noclobber (the report path is unique, but be explicit)
        printf '%s\n' "$JSON_OUTPUT" >|"$json_file"
        chmod 600 "$json_file"
        output ""
        output "JSON report saved to: $json_file"
    fi
}

# =============================================================================
# COMMAND LINE ARGUMENT PARSING
# =============================================================================

usage() {
    cat <<EOF
VPS Security Audit Tool v${VERSION}

A read-only security audit for Linux VPS servers. Run it on a new server to
find what to fix first. It never changes your configuration.

Usage: $0 [OPTIONS]

Options:
    -h, --help              Show this help message
    -v, --version           Show version information
    -q, --quiet             Suppress console output (for cron jobs)
    -o, --output DIR        Output directory for the report (default: current)
    -f, --format FORMAT     Report format: text, json, both (default: text)
    -V, --verbose           Enable verbose/debug output
    --no-color              Disable colored output (also: NO_COLOR=1)
    --guide                 Show a quick-start hardening guide for a new VPS
    --no-network            Do not contact other machines (no public IP lookup,
                            no package-index refresh, no hostname DNS lookup)
    --no-suid               Skip the SUID/SGID file scan (can be slow)
    --checks LIST           Comma-separated list of check categories to run
    --dry-run               Show which checks would run without running them

Threshold Options (percentages are 1-100):
    --disk-warn PCT         Disk usage warning threshold (default: 80)
    --disk-fail PCT         Disk usage failure threshold (default: 90)
    --mem-warn PCT          Memory usage warning threshold (default: 80)
    --mem-fail PCT          Memory usage failure threshold (default: 90)
    --login-warn NUM        Failed login warning threshold (default: 10)
    --login-fail NUM        Failed login failure threshold (default: 50)

Check Categories (for --checks):
EOF
    local entry
    for entry in "${CHECK_CATEGORIES[@]}"; do
        printf '    %-12s%s\n' "${entry%%|*}" "${entry#*|}"
    done
    cat <<EOF

Examples:
    sudo $0                         # Run all checks
    sudo $0 --guide                 # Hardening guide for a new VPS
    sudo $0 -q -f json              # Quiet, JSON report (for cron)
    sudo $0 --no-suid --no-network  # Skip slow and network parts
    sudo $0 --checks ssh,firewall   # Only these categories

Exit Codes:
    0   No check failed (warnings are allowed)
    1   One or more checks failed
    2   A critical security issue was found

Report bugs to: https://github.com/tomtom215/vps-audit/issues
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h | --help)
                usage
                exit 0
                ;;
            -v | --version)
                echo "VPS Security Audit Tool v${VERSION}"
                exit 0
                ;;
            --guide)
                CONFIG[show_guide]="true"
                ;;
            -q | --quiet)
                CONFIG[quiet]="true"
                ;;
            -o | --output)
                if [[ -n "${2:-}" ]]; then
                    CONFIG[output_dir]="$2"
                    shift
                else
                    log_error "Option $1 requires an argument"
                    exit 1
                fi
                ;;
            -f | --format)
                if [[ -n "${2:-}" ]]; then
                    case "$2" in
                        text | json | both)
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
            -V | --verbose)
                CONFIG[verbosity]="verbose"
                ;;
            --no-color)
                CONFIG[color]="false"
                ;;
            --no-network)
                CONFIG[skip_network]="true"
                ;;
            --no-suid)
                CONFIG[skip_suid_scan]="true"
                ;;
            --checks)
                if [[ -n "${2:-}" ]]; then
                    CONFIG[checks]="${2//[[:space:]]/}"
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
                if [[ -n "${2:-}" ]] && validate_percentage "$2"; then
                    THRESHOLDS[disk_warn]="$2"
                    shift
                else
                    log_error "Option $1 requires a percentage between 1-100"
                    exit 1
                fi
                ;;
            --disk-fail)
                if [[ -n "${2:-}" ]] && validate_percentage "$2"; then
                    THRESHOLDS[disk_fail]="$2"
                    shift
                else
                    log_error "Option $1 requires a percentage between 1-100"
                    exit 1
                fi
                ;;
            --mem-warn)
                if [[ -n "${2:-}" ]] && validate_percentage "$2"; then
                    THRESHOLDS[mem_warn]="$2"
                    shift
                else
                    log_error "Option $1 requires a percentage between 1-100"
                    exit 1
                fi
                ;;
            --mem-fail)
                if [[ -n "${2:-}" ]] && validate_percentage "$2"; then
                    THRESHOLDS[mem_fail]="$2"
                    shift
                else
                    log_error "Option $1 requires a percentage between 1-100"
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

    validate_check_selection

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

            # Config file must not be writable by group OR other: it is sourced
            # (executed) as root, so any non-owner writer would gain arbitrary
            # root code execution. The previous test inspected only the last
            # octal digit and let a root-owned, group-writable file (e.g. mode
            # 664) through. Mask against 022 to reject both group- and
            # other-write bits.
            if ((8#${file_perms} & 022)); then
                log_warning "Ignoring config file $config_file - writable by group/other (insecure)"
                continue
            fi

            log_debug "Loading config from: $config_file"
            # shellcheck source=/dev/null
            source "$config_file"
        fi
    done
}

# Reject unknown --checks categories. An unknown name used to match nothing, so
# a typo in a cron job silently ran an empty audit that reported "all clear".
validate_check_selection() {
    [[ "${CONFIG[checks]}" == "all" ]] && return 0
    local valid key bad=() name
    valid=" $(category_keys | tr '\n' ' ')"
    local -a requested=()
    IFS=, read -ra requested <<<"${CONFIG[checks]}"
    for name in "${requested[@]}"; do
        [[ -z "$name" ]] && continue
        [[ "$valid" == *" $name "* ]] || bad+=("$name")
    done
    if [[ ${#bad[@]} -gt 0 ]]; then
        key="$(category_keys | tr '\n' ' ')"
        log_error "Unknown check category: ${bad[*]}"
        log_error "Valid categories: ${key% }"
        exit 1
    fi
}

# Check if a specific check should run. On success the category is remembered
# so results (and the JSON report) can be attributed to it.
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

    CURRENT_CATEGORY="$check_name"
    return 0
}

# =============================================================================
# SSH CONFIGURATION CHECKS
# =============================================================================

# Cache of the effective sshd configuration as produced by `sshd -T`.
SSHD_EFFECTIVE_CONFIG=""
SSHD_EFFECTIVE_LOADED="false" # "false" until we have attempted to load
SSHD_EFFECTIVE_OK="false"     # "true" only if sshd -T succeeded

# Populate SSHD_EFFECTIVE_CONFIG from `sshd -T`, which resolves Include
# directives, Match blocks, and version-specific defaults into a single
# authoritative key/value listing (lowercased keys). This is far more reliable
# than grepping sshd_config by hand. Loaded once and cached. Returns 0 on
# success, 1 if sshd is unavailable or the config could not be dumped.
load_sshd_effective_config() {
    [[ "$SSHD_EFFECTIVE_LOADED" == "true" ]] && {
        [[ "$SSHD_EFFECTIVE_OK" == "true" ]]
        return
    }
    SSHD_EFFECTIVE_LOADED="true"

    local sshd_bin=""
    if has_command sshd; then
        sshd_bin="sshd"
    else
        local candidate
        for candidate in /usr/sbin/sshd /sbin/sshd /usr/bin/sshd /usr/local/sbin/sshd; do
            if [[ -x "$candidate" ]]; then
                sshd_bin="$candidate"
                break
            fi
        done
    fi
    [[ -z "$sshd_bin" ]] && return 1

    # `sshd -T` needs root and a parseable config. Try the plain form first.
    # Before OpenSSH 8.1 it refused to run when sshd_config had a Match block
    # whose criteria it was not given, so retry with a representative
    # connection spec (-C) before giving up.
    local out
    if out=$("$sshd_bin" -T 2>/dev/null) && [[ -n "$out" ]]; then
        SSHD_EFFECTIVE_CONFIG="$out"
        SSHD_EFFECTIVE_OK="true"
        log_debug "Loaded effective SSH config via 'sshd -T'"
        return 0
    fi
    if out=$("$sshd_bin" -T -C user=root,host=localhost,addr=127.0.0.1,lport=22 2>/dev/null) &&
        [[ -n "$out" ]]; then
        SSHD_EFFECTIVE_CONFIG="$out"
        SSHD_EFFECTIVE_OK="true"
        log_debug "Loaded effective SSH config via 'sshd -T -C ...'"
        return 0
    fi
    log_debug "sshd -T unavailable; falling back to manual sshd_config parsing"
    return 1
}

get_ssh_config() {
    local setting="$1"
    local default="$2"
    local value=""
    local config_files=()

    # Preferred path: authoritative effective configuration from `sshd -T`.
    # Keys in that output are lowercase; values may contain spaces (e.g. lists).
    if load_sshd_effective_config; then
        local key="${setting,,}"
        value=$(printf '%s\n' "$SSHD_EFFECTIVE_CONFIG" |
            awk -v k="$key" 'tolower($1)==k { $1=""; sub(/^[ \t]+/,""); print; exit }')
        if [[ -n "$value" ]]; then
            log_debug "sshd -T: $setting = $value"
            echo "$value"
            return 0
        fi
        # sshd -T succeeded but the key is absent (option unset, e.g. AllowUsers):
        # the documented default is correct, so return it without manual parsing.
        echo "$default"
        return 0
    fi

    # Fallback: best-effort manual parse (does not understand Match blocks).
    # Check for Include directives in main config
    local include_pattern
    include_pattern=$(grep -h "^Include" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)

    if [[ -n "$include_pattern" ]]; then
        local dir base file
        dir=$(dirname "$include_pattern" 2>/dev/null)
        base=$(basename "$include_pattern" 2>/dev/null)

        if [[ -d "$dir" ]]; then
            # Expand the Include glob with bash pathname expansion (already
            # sorted, and portable - avoids the GNU-only `find -print0 | sort -z`
            # that older BusyBox lacks). $base is intentionally unquoted so the
            # glob expands; non-matches are filtered out by the -f test.
            # shellcheck disable=SC2231  # deliberate glob expansion of $base
            for file in "$dir"/$base; do
                [[ -f "$file" ]] && config_files+=("$file")
            done
        fi
    fi

    # Add main config file
    config_files+=("/etc/ssh/sshd_config")

    # Search through files for the setting (first match wins). Only the GLOBAL
    # scope is considered: awk stops at the first `Match` line so a directive
    # that applies only to a specific user/host/subnet is not mistaken for the
    # global value. (The sshd -T path above already resolves this correctly;
    # this guard hardens the manual fallback.)
    for config in "${config_files[@]}"; do
        if [[ -f "$config" ]] && [[ -r "$config" ]]; then
            value=$(awk 'tolower($1)=="match"{exit} 1' "$config" 2>/dev/null |
                grep -i "^[[:space:]]*${setting}[[:space:]]" | head -1 | awk '{print $2}')
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
        prohibit-password | without-password)
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

# Succeeds if someone can log in over SSH using only an account password.
# Three settings decide it, and PasswordAuthentication is only one of them:
# keyboard-interactive authentication through PAM also asks for the account
# password (verified on a live sshd: PasswordAuthentication no +
# KbdInteractiveAuthentication yes + UsePAM yes still let a password login in),
# and AuthenticationMethods can require more than a password.
# Sets SSH_PASSWORD_PATH to "password", "keyboard-interactive" or "".
ssh_password_login_possible() {
    SSH_PASSWORD_PATH=""
    local pw kbd pam methods
    pw=$(get_ssh_config "PasswordAuthentication" "yes")
    kbd=$(get_ssh_config "KbdInteractiveAuthentication" "yes")
    # sshd -T always prints usepam when PAM is built in; builds without PAM
    # (Alpine) omit it, and then keyboard-interactive has nothing to ask.
    pam=$(get_ssh_config "UsePAM" "no")
    methods=$(get_ssh_config "AuthenticationMethods" "any")

    local pw_ok=false kbd_ok=false
    [[ "$pw" == "yes" ]] && pw_ok=true
    [[ "$kbd" == "yes" && "$pam" == "yes" ]] && kbd_ok=true

    if [[ "$methods" != "any" ]]; then
        # Space separates alternatives; a comma chains methods that must ALL
        # succeed. Only an alternative made solely of password-type methods
        # lets a password alone in.
        local alt m only_pw only_kbd pw_alt=false kbd_alt=false
        for alt in $methods; do
            only_pw=true
            only_kbd=true
            local -a seq=()
            IFS=, read -ra seq <<<"$alt"
            for m in "${seq[@]}"; do
                [[ "$m" == "password" ]] || only_pw=false
                [[ "$m" == "keyboard-interactive" || "$m" == "keyboard-interactive:pam" ]] || only_kbd=false
            done
            [[ "$only_pw" == "true" ]] && pw_alt=true
            [[ "$only_kbd" == "true" ]] && kbd_alt=true
        done
        [[ "$pw_alt" == "true" ]] || pw_ok=false
        [[ "$kbd_alt" == "true" ]] || kbd_ok=false
    fi

    if [[ "$pw_ok" == "true" ]]; then
        SSH_PASSWORD_PATH="password"
    elif [[ "$kbd_ok" == "true" ]]; then
        SSH_PASSWORD_PATH="keyboard-interactive"
    fi
    [[ -n "$SSH_PASSWORD_PATH" ]]
}

check_ssh_password_auth() {
    should_run_check "ssh" || return 0

    if ssh_password_login_possible; then
        if [[ "$SSH_PASSWORD_PATH" == "password" ]]; then
            check_security "SSH Password Auth" "WARN" "Password authentication is enabled" \
                "Set 'PasswordAuthentication no' (after confirming key login works) so only SSH keys are accepted"
        else
            check_security "SSH Password Auth" "WARN" \
                "PasswordAuthentication is off, but keyboard-interactive login through PAM still accepts the account password" \
                "Set 'KbdInteractiveAuthentication no' (or 'AuthenticationMethods publickey') in addition to 'PasswordAuthentication no'"
        fi
    else
        check_security "SSH Password Auth" "PASS" "Password logins are disabled (key-based only)" ""
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
# FIREWALL CHECKS
# =============================================================================
#
# A host counts as firewalled only if inbound traffic is default-denied: a
# base chain on the input hook with policy drop, or an unconditional trailing
# drop/reject. Merely having chains or rules is not enough - Docker creates
# nftables/iptables chains on every host, and fail2ban's input chain only
# rejects already-banned addresses - so counting chains or rules reported
# "firewall active" on hosts with no firewall at all.

# Read `nft list ruleset` on stdin; succeed if a base chain on the input hook,
# in a table whose family matches the extended regex $1 (e.g. "ip|inet"),
# default-denies inbound traffic.
nft_input_default_deny() {
    awk -v fam="^($1)$" '
        /^table /          { tfam = $2; next }
        /^[ \t]*chain /    { hook = 0; next }
        /hook input/       {
            if (tfam ~ fam) {
                hook = 1
                if ($0 ~ /policy (drop|reject)/) found = 1
            }
            next
        }
        hook && /^[ \t]*(counter( packets [0-9]+ bytes [0-9]+)?[ \t]+)?(drop|reject)([ \t]+with[ \t].*)?[ \t]*$/ { found = 1 }
        /^[ \t]*}/         { hook = 0 }
        END                { exit(found ? 0 : 1) }
    '
}

# Succeed if iptables/ip6tables (command name in $1) default-denies inbound
# traffic: INPUT policy DROP/REJECT, or an unconditional final DROP/REJECT rule.
iptables_input_default_deny() {
    local rules
    rules=$("$1" -S INPUT 2>/dev/null) || return 1
    grep -qE '^-P INPUT (DROP|REJECT)' <<<"$rules" && return 0
    grep '^-A INPUT ' <<<"$rules" | tail -n 1 | grep -qE '^-A INPUT -j (DROP|REJECT)( |$)'
}

# Succeed if UFW is active and does not default-allow inbound traffic.
ufw_is_protecting() {
    has_command ufw || return 1
    local out
    out=$(ufw status verbose 2>/dev/null) || return 1
    grep -qw 'active' <<<"$out" || return 1
    ! grep -qiE '^Default:.*allow \(incoming\)' <<<"$out"
}

firewalld_is_running() {
    has_command firewall-cmd || return 1
    firewall-cmd --state 2>/dev/null | grep 'running' >/dev/null
}

check_firewall_status() {
    should_run_check "firewall" || return 0

    local active="" detail=""
    local -a installed=()

    if has_command ufw; then
        installed+=("UFW")
        if ufw_is_protecting; then
            active="UFW"
            detail="UFW is active and denies inbound traffic by default"
        fi
    fi
    if [[ -z "$active" ]] && has_command firewall-cmd; then
        installed+=("firewalld")
        if firewalld_is_running; then
            active="firewalld"
            detail="firewalld is running"
        fi
    fi
    if [[ -z "$active" ]] && has_command nft; then
        installed+=("nftables")
        if nft list ruleset 2>/dev/null | nft_input_default_deny "ip|inet"; then
            active="nftables"
            detail="nftables denies inbound traffic by default"
        fi
    fi
    if [[ -z "$active" ]] && has_command iptables; then
        installed+=("iptables")
        if iptables_input_default_deny iptables; then
            active="iptables"
            detail="iptables denies inbound traffic by default"
        fi
    fi

    local provider_note="A cloud provider's network firewall (security groups) is not visible to this script."
    if [[ -n "$active" ]]; then
        check_security "Firewall Status ($active)" "PASS" "$detail" ""
    elif [[ ${#installed[@]} -eq 0 ]]; then
        check_security "Firewall Status" "FAIL" "No host firewall tool found (ufw, firewalld, nftables, iptables)" \
            "Install and enable a host firewall, e.g. 'apt install ufw && ufw default deny incoming && ufw allow ssh && ufw enable'. $provider_note" "true"
    else
        local names="${installed[*]}"
        check_security "Firewall Status" "FAIL" "Installed (${names// /, }) but inbound traffic is not default-denied" \
            "Set a default-deny inbound policy and allow only the ports you need, e.g. 'ufw default deny incoming && ufw allow ssh && ufw enable'. $provider_note" "true"
    fi
}

# =============================================================================
# INTRUSION PREVENTION CHECK
# =============================================================================

# Intrusion prevention that actually blocks something:
#   fail2ban  running AND at least one jail enabled (some distributions ship
#             every jail disabled);
#   CrowdSec  the engine only detects - a firewall bouncer does the blocking.
# Without any, the verdict depends on whether SSH accepts passwords at all: with
# key-only SSH there is little for these tools to protect.
check_intrusion_prevention() {
    should_run_check "ips" || return 0

    local protecting="" problem=""

    if pkg_installed fail2ban; then
        if service_is_active fail2ban; then
            local jails
            jails=$(fail2ban-client status 2>/dev/null | awk -F: '/Number of jail/ {gsub(/[[:space:]]/, "", $2); print $2; exit}')
            if is_numeric "$jails" && [[ $jails -eq 0 ]]; then
                problem="fail2ban is running but has no jails enabled"
            else
                protecting="Fail2ban"
            fi
        else
            problem="fail2ban is installed but not running"
        fi
    fi

    if pkg_installed crowdsec; then
        if service_is_active crowdsec; then
            if pkg_installed crowdsec-firewall-bouncer-nftables || pkg_installed crowdsec-firewall-bouncer-iptables ||
                pkg_installed crowdsec-firewall-bouncer || service_is_active crowdsec-firewall-bouncer; then
                protecting="${protecting:+$protecting/}CrowdSec"
            else
                problem="${problem:+$problem; }CrowdSec is running without a firewall bouncer, so it detects but does not block"
            fi
        else
            problem="${problem:+$problem; }CrowdSec is installed but not running"
        fi
    fi

    # Containerised fail2ban/CrowdSec
    if has_command docker && service_is_active docker 2>/dev/null; then
        if docker ps --format '{{.Image}}' 2>/dev/null | grep -iE "fail2ban|crowdsec" >/dev/null; then
            protecting="${protecting:+$protecting/}container"
        fi
    fi

    if [[ -n "$protecting" ]]; then
        check_security "Intrusion Prevention" "PASS" "$protecting is running and blocking" ""
    elif [[ -n "$problem" ]]; then
        check_security "Intrusion Prevention" "WARN" "$problem" \
            "Enable at least one jail (e.g. 'sshd') in /etc/fail2ban/jail.d/, or install a CrowdSec firewall bouncer"
    elif ssh_password_login_possible; then
        check_security "Intrusion Prevention" "WARN" "No intrusion prevention found while SSH accepts passwords" \
            "Install fail2ban ('apt install fail2ban') or CrowdSec, or switch SSH to keys only"
    else
        check_security "Intrusion Prevention" "INFO" "No intrusion prevention found (SSH is key-only, so less is exposed)" \
            "Optional: install fail2ban or CrowdSec to cut brute-force noise"
    fi
}

# =============================================================================
# AUTO-UPDATES CHECK
# =============================================================================

# Value of an APT::Periodic setting (empty if unset), via apt-config so every
# drop-in under /etc/apt/apt.conf.d is honoured.
apt_periodic_value() {
    apt-config dump 2>/dev/null | awk -F'"' -v k="APT::Periodic::$1 " '$1 == k {print $2; exit}'
}

# True if a dnf/yum automatic.conf sets apply_updates to a truthy value.
automatic_conf_applies_updates() {
    local v
    v=$(awk -F= '/^[[:space:]]*apply_updates[[:space:]]*=/ {gsub(/[[:space:]]/, "", $2); print tolower($2); exit}' "$1" 2>/dev/null)
    [[ "$v" == "yes" || "$v" == "true" || "$v" == "1" ]]
}

# Are automatic security updates actually ENABLED - not merely installed?
#   apt:    unattended-upgrades installed AND APT::Periodic::Update-Package-Lists
#           and ::Unattended-Upgrade above 0 ("0 disables the action").
#   dnf:    an install timer, or the default timer with apply_updates = yes
#           (the default timer only downloads).
# Other package managers have no reliable test, so the result is INFO.
check_auto_updates() {
    should_run_check "updates" || return 0

    case "${OS_INFO[pkg_manager]}" in
        apt)
            if ! pkg_installed unattended-upgrades; then
                check_security "Automatic Updates" "WARN" "unattended-upgrades is not installed" \
                    "Run 'apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades'"
                return 0
            fi
            local lists upgrade
            lists=$(apt_periodic_value "Update-Package-Lists")
            upgrade=$(apt_periodic_value "Unattended-Upgrade")
            if is_numeric "$lists" && is_numeric "$upgrade" && [[ $lists -gt 0 && $upgrade -gt 0 ]]; then
                check_security "Automatic Updates" "PASS" "Automatic security updates are enabled (unattended-upgrades)" ""
            else
                check_security "Automatic Updates" "WARN" \
                    "unattended-upgrades is installed but disabled (Update-Package-Lists=${lists:-unset}, Unattended-Upgrade=${upgrade:-unset})" \
                    "Run 'dpkg-reconfigure -plow unattended-upgrades', or set both values to \"1\" in /etc/apt/apt.conf.d/20auto-upgrades"
            fi
            ;;
        dnf | yum)
            local unit installing="" downloading=""
            for unit in dnf-automatic-install.timer dnf5-automatic-install.timer; do
                service_is_active "$unit" 2>/dev/null && installing="$unit"
            done
            for unit in dnf-automatic.timer dnf5-automatic.timer yum-cron; do
                service_is_active "$unit" 2>/dev/null && downloading="$unit"
            done
            local conf="$DNF_AUTOMATIC_CONF"
            [[ "$downloading" == "yum-cron" ]] && conf="/etc/yum/yum-cron.conf"
            if [[ -n "$installing" ]] || { [[ -n "$downloading" ]] && automatic_conf_applies_updates "$conf"; }; then
                check_security "Automatic Updates" "PASS" "Automatic updates are enabled (${installing:-$downloading})" ""
            elif [[ -n "$downloading" ]]; then
                check_security "Automatic Updates" "WARN" \
                    "${downloading} is running but does not install updates (apply_updates is not yes)" \
                    "Set 'apply_updates = yes' in $conf, or enable dnf-automatic-install.timer"
            else
                check_security "Automatic Updates" "WARN" "Automatic updates are not enabled" \
                    "Run 'dnf install dnf-automatic && systemctl enable --now dnf-automatic-install.timer'"
            fi
            ;;
        *)
            check_security "Automatic Updates" "INFO" \
                "Automatic updates cannot be detected for ${OS_INFO[pkg_manager]}" ""
            ;;
    esac
}

# =============================================================================
# SYSTEM UPDATES CHECK
# =============================================================================

check_system_updates() {
    should_run_check "updates" || return 0

    show_progress "Checking for system updates"

    # apt answers from its local index. An empty or old index makes "0 updates"
    # meaningless, so look at it before trusting the count.
    local index_note=""
    if [[ "${OS_INFO[pkg_manager]}" == "apt" ]]; then
        local lists
        lists=$(find "$APT_LISTS_DIR" -maxdepth 1 -name '*Packages*' 2>/dev/null | count_lines)
        if [[ "$lists" -eq 0 ]]; then
            clear_progress
            check_security "System Updates" "WARN" \
                "The package index is empty, so pending updates cannot be determined" \
                "Run 'apt update' and re-run the audit"
            return 0
        fi
        local mtime age_days
        mtime=$(sanitize_int "$(portable_stat mtime "$APT_UPDATE_STAMP")")
        if [[ $mtime -gt 0 ]]; then
            age_days=$((($(date +%s) - mtime) / 86400))
            [[ $age_days -gt 7 ]] && index_note=" (package index is ${age_days} days old; run 'apt update' for current data)"
        fi
    fi

    local total_updates
    local security_updates

    total_updates=$(get_update_count)
    security_updates=$(get_security_update_count)

    clear_progress

    if ! is_numeric "$total_updates"; then
        check_security "System Updates" "WARN" "Unable to determine update status" \
            "Check the package manager manually"
        return
    fi

    if [[ $total_updates -eq 0 ]]; then
        if [[ -n "$index_note" ]]; then
            check_security "System Updates" "WARN" "No updates pending${index_note}" "Run 'apt update' and re-run the audit"
        else
            check_security "System Updates" "PASS" "All packages are up to date" ""
        fi
    elif is_numeric "$security_updates" && [[ $security_updates -gt 0 ]]; then
        check_security "System Updates" "FAIL" "$security_updates security $(plural "$security_updates" update updates) available (${total_updates} total)${index_note}" \
            "Install them now with '$(upgrade_command)' and reboot if a kernel or libc was updated"
    else
        check_security "System Updates" "WARN" "$total_updates $(plural "$total_updates" update updates) available${index_note}" \
            "Install them soon with '$(upgrade_command)'"
    fi
}

# =============================================================================
# FAILED LOGINS CHECK
# =============================================================================

# Failed SSH logins in the last 24 hours (journal) or today (log file). What an
# attack looks like in the log depends on the configuration: with password
# authentication OFF - the recommended state - attempts log as "Invalid user"
# and "Connection closed by authenticating user ... [preauth]" and never as
# "Failed password", so all three shapes are counted.
check_failed_logins() {
    should_run_check "logins" || return 0

    local pattern='Failed password for|Invalid user |Connection (closed|reset) by authenticating user'
    local failed_count=0 log_source="" journal_ok=false

    # Prefer the systemd journal when it is actually READABLE. Probing with
    # `journalctl -n0` first means a legitimate zero count is trusted instead
    # of falling through to "unable to read logs" on a journald-only host.
    if [[ "${OS_INFO[service_manager]}" == "systemd" ]] && has_command journalctl &&
        journalctl -n0 &>/dev/null; then
        journal_ok=true
        failed_count=$(journalctl -u sshd -u ssh --since "24 hours ago" 2>/dev/null |
            grep -cE "$pattern" || true)
        failed_count=$(sanitize_int "$failed_count")
        log_source="journalctl, last 24h"
    fi

    if [[ "$journal_ok" == "false" ]]; then
        local log_files=("${OS_INFO[auth_log]}" /var/log/auth.log /var/log/secure /var/log/messages)
        # %e space-pads single-digit days, so syslog writes "Jul  5" (two
        # spaces); match one-or-more spaces between month and day.
        local mon day log_file
        mon=$(date +%b)
        day=$(date +%e | tr -d ' ')
        for log_file in "${log_files[@]}"; do
            if [[ -n "$log_file" && -f "$log_file" && -r "$log_file" ]]; then
                failed_count=$(grep -E "^${mon}[[:space:]]+${day}[[:space:]]" "$log_file" 2>/dev/null |
                    grep -cE "$pattern" || true)
                failed_count=$(sanitize_int "$failed_count")
                log_source="$log_file, today"
                break
            fi
        done
    fi

    if [[ -z "$log_source" ]]; then
        check_security "Failed Logins" "WARN" "Unable to read authentication logs" \
            "No readable journal, /var/log/auth.log, /var/log/secure or /var/log/messages: install rsyslog or enable persistent journald storage so login attempts are recorded"
        return
    fi

    local msg
    msg="$failed_count failed login log $(plural "$failed_count" entry entries) ($log_source)"
    if [[ $failed_count -lt ${THRESHOLDS[failed_logins_warn]} ]]; then
        check_security "Failed Logins" "PASS" "$msg" ""
    elif [[ $failed_count -lt ${THRESHOLDS[failed_logins_fail]} ]]; then
        check_security "Failed Logins" "WARN" "$msg" \
            "Expected on any public server; reduce it with key-only SSH and fail2ban, and check 'lastb'/the journal for a pattern"
    else
        check_security "Failed Logins" "FAIL" "$msg" \
            "A sustained brute-force attempt: switch SSH to keys only, enable fail2ban, and consider a non-default port or allow-listing source addresses"
    fi
}

# =============================================================================
# RUNNING SERVICES CHECK
# =============================================================================

# Running Services Check. A count has no pass/fail threshold (a Docker or web
# host legitimately runs dozens), so it is reported as INFO. Zero means the
# service manager is not reporting - a container, or an init system we cannot
# query - and is reported as such rather than as "minimal attack surface".
check_running_services() {
    should_run_check "services" || return 0

    local service_count
    service_count=$(get_running_services_count)

    if ! is_numeric "$service_count"; then
        check_security "Running Services" "WARN" "Unable to count running services" ""
        return
    fi

    if [[ $service_count -eq 0 ]]; then
        check_security "Running Services" "WARN" \
            "No running services were reported by the service manager (${OS_INFO[service_manager]}); cannot assess" ""
        return
    fi

    check_security "Running Services" "INFO" "$service_count $(plural "$service_count" "service is" "services are") running" \
        "Review them ('systemctl list-units --type=service --state=running') and disable what you do not use"
}

# =============================================================================
# PORT SECURITY CHECK
# =============================================================================

# Classify a listen/bind address as network-reachable ("public") or not
# ("local"). Input is a bare address with any IPv6 brackets already stripped.
# Loopback (including 127.0.0.53 from systemd-resolved), RFC1918, link-local,
# and unique-local ranges are "local"; wildcard binds and routable addresses
# are "public". Kept as a standalone pure function so it is unit-testable.
classify_bind_scope() {
    local addr="$1"
    case "$addr" in
        127.* | ::1 | localhost | "")
            echo "local"
            return
            ;;
        0.0.0.0 | :: | \* | ::ffff:0.0.0.0)
            echo "public"
            return
            ;;
    esac
    if [[ "$addr" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.|fe80:|f[cd]) ]]; then
        echo "local"
    else
        echo "public"
    fi
}

# Publicly reachable listening ports, with the process behind each. "Public"
# means bound to a wildcard or routable address (classify_bind_scope);
# loopback and private-range listeners are counted separately. DHCP-client UDP
# sockets (port 68, bound to the interface address) are not services and are
# ignored.
check_open_ports() {
    should_run_check "ports" || return 0

    local listening_info=""
    if has_command ss; then
        listening_info=$(ss -tulnp 2>/dev/null)
    elif has_command netstat; then
        listening_info=$(netstat -tulnp 2>/dev/null)
    else
        check_security "Port Security" "WARN" "Neither ss nor netstat is available" \
            "Install iproute2 (ss) or net-tools (netstat)"
        return
    fi

    if [[ -z "$listening_info" ]]; then
        check_security "Port Security" "WARN" "Unable to retrieve listening ports" ""
        return
    fi

    # One line per socket: PROTO LOCAL-ADDRESS:PORT PROCESS
    local -A public_ports=() local_ports=()
    local proto local_addr proc addr port
    while read -r proto local_addr proc; do
        [[ -z "$local_addr" ]] && continue
        port="${local_addr##*:}"
        addr="${local_addr%:*}"
        addr="${addr#\[}"
        addr="${addr%\]}"
        addr="${addr%%\%*}"
        is_numeric "$port" || continue
        [[ "$proto" == udp* && "$port" == "68" ]] && continue

        if [[ "$(classify_bind_scope "$addr")" == "public" ]]; then
            public_ports["$port"]="${proc:-?}"
        else
            local_ports["$port"]=1
        fi
    done < <(printf '%s\n' "$listening_info" | awk '
        $1 ~ /^(tcp|udp)/ {
            local_col = ($5 ~ /:[0-9*]+$/) ? $5 : $4
            proc = ""
            if (match($0, /users:\(\("[^"]+"/)) {
                proc = substr($0, RSTART + 9, RLENGTH - 9)
                sub(/^"/, "", proc); sub(/"$/, "", proc)
            } else if (match($0, /[0-9]+\/[^ ]+$/)) {
                proc = substr($0, RSTART, RLENGTH); sub(/^[0-9]+\//, "", proc)
            }
            print $1, local_col, proc
        }')

    # Ports that are both public and local-only count once, as public.
    local p
    for p in "${!public_ports[@]}"; do
        unset "local_ports[$p]"
    done

    local public_count=${#public_ports[@]} local_count=${#local_ports[@]}
    local total=$((public_count + local_count))
    local -a items=()
    if [[ $public_count -gt 0 ]]; then
        while IFS= read -r p; do
            items+=("$p/${public_ports[$p]}")
        done < <(printf '%s\n' "${!public_ports[@]}" | sort -n)
    fi
    local list="${items[*]}"
    list="${list// /, }"
    local msg="Public: ${public_count}${list:+ ($list)}; local-only: ${local_count}"

    if [[ $public_count -lt ${THRESHOLDS[public_ports_warn]} ]] &&
        [[ $total -lt ${THRESHOLDS[ports_warn]} ]]; then
        check_security "Port Security" "PASS" "$msg" ""
    elif [[ $public_count -lt ${THRESHOLDS[public_ports_fail]} ]] &&
        [[ $total -lt ${THRESHOLDS[ports_fail]} ]]; then
        check_security "Port Security" "WARN" "$msg" \
            "Close or firewall what you do not need, and bind internal services to 127.0.0.1"
    else
        check_security "Port Security" "FAIL" "$msg" \
            "Too many publicly reachable ports: close what you do not need and bind internal services to 127.0.0.1"
    fi
}

# =============================================================================
# RESOURCE USAGE CHECKS
# =============================================================================

check_disk_usage() {
    should_run_check "resources" || return 0

    # -P forces POSIX one-line-per-filesystem output; without it, a long device
    # name (LVM /dev/mapper/..., ZFS, overlay) wraps onto a second physical line
    # and `awk NR==2` would read the wrapped name instead of the data row.
    local disk_info
    disk_info=$(df -hP / 2>/dev/null | awk 'NR==2')

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

# CPU Usage. A one-second /proc/stat sample is a snapshot, not a verdict: it is
# shown for context and never scored.
check_cpu_usage() {
    should_run_check "resources" || return 0

    local cpu_usage=0

    if [[ -f /proc/stat ]]; then
        # /proc/stat fields: cpu user nice system idle iowait irq softirq steal
        # active = user+nice+system+irq+softirq+steal (2,3,4,7,8,9); idle = idle+iowait (5,6)
        # A whole second (not a fractional sleep, which some BusyBox builds lack)
        # keeps the two samples distinct.
        local cpu1 cpu2
        cpu1=$(head -1 /proc/stat | awk '{print $2+$3+$4+$7+$8+$9, $5+$6}')
        sleep 1
        cpu2=$(head -1 /proc/stat | awk '{print $2+$3+$4+$7+$8+$9, $5+$6}')

        local active1 idle1 active2 idle2
        read -r active1 idle1 <<<"$cpu1"
        read -r active2 idle2 <<<"$cpu2"

        local active_diff=$((active2 - active1))
        local idle_diff=$((idle2 - idle1))
        local total_diff=$((active_diff + idle_diff))
        if [[ $total_diff -gt 0 ]]; then
            cpu_usage=$((active_diff * 100 / total_diff))
        fi
    fi

    local cpu_cores load_avg
    cpu_cores=$(get_cpu_cores || echo "?")
    load_avg=$(get_load_average 1min)
    check_security "CPU Usage" "INFO" "${cpu_usage}% busy over 1 second (Cores: ${cpu_cores}, Load: ${load_avg:-?})" ""
}

# =============================================================================
# SUDO LOGGING CHECK
# =============================================================================

# Sudo Logging Check. sudo logs to syslog (the journal on systemd hosts) unless
# told otherwise, so only an explicit opt-out is a finding.
check_sudo_logging() {
    should_run_check "sudo" || return 0

    local -a files=("$SUDOERS_FILE" "$SUDOERS_RS")
    local f
    if [[ -d "$SUDOERS_DIR" ]]; then
        while IFS= read -r f; do
            files+=("$f")
        done < <(find "$SUDOERS_DIR" -maxdepth 1 -type f 2>/dev/null)
    fi

    local disabled=false logged_elsewhere=false
    for f in "${files[@]}"; do
        [[ -r "$f" ]] || continue
        grep -qE '^Defaults[[:space:]]+(.*,)?!syslog' "$f" 2>/dev/null && disabled=true
        grep -qE '^Defaults[[:space:]].*(logfile|log_output|log_input)' "$f" 2>/dev/null && logged_elsewhere=true
    done

    if [[ "$disabled" == "true" && "$logged_elsewhere" == "false" ]]; then
        check_security "Sudo Logging" "WARN" "sudo logging to syslog is explicitly disabled" \
            "Remove 'Defaults !syslog' from sudoers, or add 'Defaults logfile=/var/log/sudo.log'"
    else
        check_security "Sudo Logging" "PASS" "sudo commands are logged" ""
    fi
}

# =============================================================================
# PASSWORD POLICY CHECK
# =============================================================================

# Resolve a pwquality setting (minlen, ...) from every place a distro may
# configure it: pwquality.conf, its .conf.d drop-ins, and inline pam_pwquality /
# pam_cracklib arguments in /etc/pam.d/*. Prints the effective value (last
# definition wins), or nothing if unset.
get_pwquality_setting() {
    local name="$1" value="" f v
    local files=()
    [[ -f "$PWQUALITY_CONF" ]] && files+=("$PWQUALITY_CONF")
    if [[ -d "$PWQUALITY_CONF_D" ]]; then
        for f in "$PWQUALITY_CONF_D"/*.conf; do
            [[ -f "$f" ]] && files+=("$f")
        done
    fi
    for f in "${files[@]}"; do
        [[ -r "$f" ]] || continue
        v=$(grep -E "^[[:space:]]*${name}[[:space:]]*=" "$f" 2>/dev/null |
            tail -1 | cut -d= -f2 | tr -d '[:space:]')
        [[ -n "$v" ]] && value="$v"
    done
    if [[ -d "$PAM_DIR" ]]; then
        v=$(grep -rhE "^[^#]*pam_(pwquality|cracklib)\.so" "$PAM_DIR" 2>/dev/null |
            grep -oE "${name}=-?[0-9]+" | tail -1 | cut -d= -f2)
        [[ -n "$v" ]] && value="$v"
    fi
    echo "$value"
}

# Password Policy Check. What matters is that a quality module is active and
# enforces a sensible minimum length (12+). Mandatory character classes are
# deliberately not required: NIST SP 800-63B advises against composition rules,
# and long passphrases satisfy this check. With key-only SSH there is no remote
# password to protect, so the result is INFO.
check_password_policy() {
    should_run_check "password" || return 0

    if ! ssh_password_login_possible; then
        check_security "Password Policy" "INFO" \
            "SSH accepts keys only, so password quality matters little for remote logins" ""
        return 0
    fi

    local module=""
    if [[ -d "$PAM_DIR" ]]; then
        module=$(grep -rhoE '^[[:space:]]*password[^#]*pam_(pwquality|passwdqc)\.so' "$PAM_DIR" 2>/dev/null |
            grep -oE 'pam_(pwquality|passwdqc)' | head -1)
    fi

    if [[ -z "$module" ]]; then
        check_security "Password Policy" "WARN" \
            "No password quality module (pam_pwquality or pam_passwdqc) is active" \
            "Install libpam-pwquality (or libpwquality) and set 'minlen = 12' in /etc/security/pwquality.conf"
        return 0
    fi
    if [[ "$module" == "pam_passwdqc" ]]; then
        check_security "Password Policy" "PASS" "pam_passwdqc enforces password quality" ""
        return 0
    fi

    local minlen
    minlen=$(get_pwquality_setting minlen)
    if is_numeric "$minlen" && [[ $minlen -ge 12 ]]; then
        check_security "Password Policy" "PASS" "pam_pwquality requires at least $minlen characters" ""
    elif is_numeric "$minlen"; then
        check_security "Password Policy" "WARN" "pam_pwquality minimum length is $minlen (12 or more is recommended)" \
            "Set 'minlen = 12' in /etc/security/pwquality.conf"
    else
        check_security "Password Policy" "WARN" "pam_pwquality is active but no minimum length is configured" \
            "Set 'minlen = 12' in /etc/security/pwquality.conf"
    fi
}

# =============================================================================
# FILESYSTEM SCANNING HELPERS
# =============================================================================

# Print the mount points a file scan should cover, one per line. `find /
# -xdev` alone only covers the root filesystem, so SUID files on a separate
# /home, /var or /opt partition were never examined. Disk-backed filesystems
# only (no proc/sys/network/overlay mounts); "/" is always included because a
# container's root filesystem is an overlay.
#
# With mode "suid", mounts flagged nosuid are skipped (they cannot hold an
# effective SUID/SGID binary) and tmpfs/ramfs without nosuid are added, since
# /tmp is where attackers drop SUID binaries.
list_local_mountpoints() {
    local mode="${1:-}"
    local mp fstype opts _
    local -A seen=(["/"]=1)
    printf '%s\n' "/"
    while read -r _ mp fstype opts _; do
        # /proc/mounts escapes space, tab and backslash as octal.
        mp="${mp//\\040/ }"
        mp="${mp//\\011/$'\t'}"
        mp="${mp//\\134/\\}"
        [[ "$mp" == "/" ]] && continue
        case "$fstype" in
            ext2 | ext3 | ext4 | xfs | btrfs | zfs | f2fs | jfs | reiserfs) ;;
            tmpfs | ramfs)
                [[ "$mode" == "suid" ]] || continue
                ;;
            *) continue ;;
        esac
        if [[ "$mode" == "suid" && ",$opts," == *",nosuid,"* ]]; then
            continue
        fi
        # Stacked mounts list the same mount point more than once.
        [[ -n "${seen[$mp]+x}" ]] && continue
        seen["$mp"]=1
        printf '%s\n' "$mp"
    done <"$PROC_MOUNTS"
}

# Directories that hold container image layers and volumes. On a Docker host
# they contain hundreds of copies of every SUID binary, and scanning them
# drowns the real findings (measured: 125 container-layer SUID files next to
# 11 genuine ones after pulling a single image). Docker's data root may be
# customised, so ask the daemon when it is available.
CONTAINER_STORAGE_PATHS=()
CONTAINER_STORAGE_LOADED=false
load_container_storage_paths() {
    [[ "$CONTAINER_STORAGE_LOADED" == "true" ]] && return 0
    CONTAINER_STORAGE_LOADED=true
    CONTAINER_STORAGE_PATHS=(
        /var/lib/docker /var/lib/containerd /var/lib/containers
        /var/lib/lxc /var/lib/lxd /var/lib/incus
    )
    if has_command docker && has_command timeout; then
        local root
        root=$(timeout 5 docker info --format '{{.DockerRootDir}}' 2>/dev/null)
        [[ "$root" == /* ]] && CONTAINER_STORAGE_PATHS+=("$root")
    fi
}

# Run `find` on one mount point without leaving its filesystem and without
# entering container storage. Usage: find_in_mount MOUNTPOINT EXPRESSION...
find_in_mount() {
    local mp="$1"
    shift
    load_container_storage_paths
    local -a prune=()
    local p
    for p in "${CONTAINER_STORAGE_PATHS[@]}"; do
        prune+=(-o -path "$p")
    done
    find "$mp" -xdev \( "${prune[@]:1}" \) -prune -o "$@" 2>/dev/null
}

# Find files matching a `find -perm` expression ($2) on every local mount.
# $1 is the list_local_mountpoints mode. Usage: find_files_by_perm suid -4000
find_files_by_perm() {
    local mode="$1" perm="$2" mp
    while IFS= read -r mp; do
        [[ -d "$mp" ]] || continue
        find_in_mount "$mp" -type f -perm "$perm" -print
    done < <(list_local_mountpoints "$mode")
}

# =============================================================================
# SUID / SGID FILES CHECK
# =============================================================================

# SUID/SGID binaries that ship with the distributions we test (taken from the
# results of auditing a stock install of each - see tests/matrix.sh). Matching
# is by exact full path: a suffix or regex match would also exempt a PLANTED
# binary such as /opt/evil/bin/su.
KNOWN_SAFE_SUID=(
    /usr/bin/sudo /usr/bin/sudo.ws /usr/bin/su /usr/bin/passwd /usr/bin/chsh
    /usr/bin/chfn /usr/bin/newgrp /usr/bin/gpasswd /usr/bin/mount
    /usr/bin/umount /usr/bin/ping /usr/bin/ping6 /usr/bin/pkexec
    /usr/bin/crontab /usr/bin/at /usr/bin/expiry /usr/bin/chage
    /usr/bin/wall /usr/bin/write /usr/bin/ssh-agent /usr/bin/staprun
    /usr/bin/fusermount /usr/bin/fusermount3 /usr/bin/newuidmap
    /usr/bin/newgidmap /usr/bin/ksu /usr/bin/unix_chkpwd
    /usr/bin/pam_timestamp_check
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper /usr/lib/dbus-daemon-launch-helper
    /usr/libexec/dbus-1/dbus-daemon-launch-helper
    /usr/lib/openssh/ssh-keysign /usr/lib/ssh/ssh-keysign
    /usr/libexec/openssh/ssh-keysign
    /usr/lib/policykit-1/polkit-agent-helper-1
    /usr/lib/polkit-1/polkit-agent-helper-1 /usr/libexec/polkit-agent-helper-1
    /usr/sbin/pppd /usr/sbin/unix_chkpwd /usr/sbin/postdrop /usr/sbin/postqueue
    /usr/sbin/pam_timestamp_check /usr/sbin/userhelper
    /usr/sbin/mount.nfs
    # Compatibility paths (non-merged-/usr systems)
    /bin/su /bin/mount /bin/umount /bin/ping /bin/ping6 /sbin/unix_chkpwd
)
KNOWN_SAFE_SGID=(
    /usr/bin/wall /usr/bin/write /usr/bin/ssh-agent /usr/bin/expiry
    /usr/bin/chage /usr/bin/crontab /usr/bin/bsd-write /usr/bin/mlocate
    /usr/sbin/unix_chkpwd /usr/sbin/postdrop /usr/sbin/postqueue
    # Measured on the stock images in tests/matrix.sh: Ubuntu (extrausers),
    # RHEL family and Amazon Linux (utempter, ssh-keysign), Arch.
    /usr/sbin/pam_extrausers_chkpwd /usr/bin/unix_chkpwd
    /usr/libexec/utempter/utempter /usr/libexec/openssh/ssh-keysign
)

# Scan every local mount for SUID or SGID files and report the ones outside the
# known-safe list.
# Usage: scan_special_files SUID|SGID SAFE_PATH...
scan_special_files() {
    local kind="$1" perm
    shift
    [[ "$kind" == "SUID" ]] && perm=-4000 || perm=-2000

    local -A safe=()
    local f
    for f in "$@"; do
        safe["$f"]=1
    done

    local -a unexpected=()
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        [[ -n "${safe[$f]+x}" ]] && continue
        unexpected+=("$f")
    done < <(find_files_by_perm suid "$perm")

    local count=${#unexpected[@]}
    if [[ $count -eq 0 ]]; then
        check_security "${kind} Files" "PASS" "No unexpected ${kind} files found" ""
        return 0
    fi

    local shown="${unexpected[*]:0:3}" more=""
    [[ $count -gt 3 ]] && more=" (and $((count - 3)) more; see the report)"
    local bit="u-s"
    [[ "$kind" == "SGID" ]] && bit="g-s"
    check_security "${kind} Files" "WARN" \
        "Found $count ${kind} $(plural "$count" file files) outside the standard set: ${shown// /, }${more}" \
        "Check that each is expected ('dpkg -S FILE' or 'rpm -qf FILE' shows the owning package); remove the bit from any that is not ('chmod ${bit} FILE')"
    {
        echo "${kind} files outside the standard set:"
        printf '  %s\n' "${unexpected[@]}"
    } >>"$REPORT_FILE"
}

check_suid_files() {
    should_run_check "suid" || return 0
    if [[ "${CONFIG[skip_suid_scan]}" == "true" ]]; then
        log_verbose "Skipping SUID/SGID scan (--no-suid)"
        return 0
    fi
    show_progress "Scanning for SUID files"
    scan_special_files SUID "${KNOWN_SAFE_SUID[@]}"
    clear_progress
}

check_sgid_files() {
    should_run_check "suid" || return 0
    [[ "${CONFIG[skip_suid_scan]}" == "true" ]] && return 0
    show_progress "Scanning for SGID files"
    scan_special_files SGID "${KNOWN_SAFE_SGID[@]}"
    clear_progress
}

# =============================================================================
# OPERATING SYSTEM SUPPORT STATUS
# =============================================================================

# End-of-support dates for Ubuntu and Debian, whose /etc/os-release has no
# SUPPORT_END. "key|standard end|extended end": standard = free security
# support; extended = the last date anything is published (Ubuntu Pro ESM /
# Debian LTS). Source: https://endoflife.date. Regenerate with
# tools/update-eol-table.sh (CI checks it weekly).
# BEGIN EOL TABLE (generated by tools/update-eol-table.sh)
readonly -a EOL_TABLE=(
    "debian:9|2020-07-18|2022-07-01"
    "debian:10|2022-09-10|2024-06-30"
    "debian:11|2024-08-14|2026-08-31"
    "debian:12|2026-07-11|2028-06-30"
    "debian:13|2028-08-09|2030-06-30"
    "ubuntu:16.04|2021-04-02|2026-04-02"
    "ubuntu:16.10|2017-07-20|2017-07-20"
    "ubuntu:17.04|2018-01-13|2018-01-13"
    "ubuntu:17.10|2018-07-19|2018-07-19"
    "ubuntu:18.04|2023-05-31|2028-04-26"
    "ubuntu:18.10|2019-07-18|2019-07-18"
    "ubuntu:19.04|2020-01-23|2020-01-23"
    "ubuntu:19.10|2020-07-06|2020-07-06"
    "ubuntu:20.04|2025-05-31|2030-04-23"
    "ubuntu:20.10|2021-07-22|2021-07-22"
    "ubuntu:21.04|2022-01-20|2022-01-20"
    "ubuntu:21.10|2022-07-14|2022-07-14"
    "ubuntu:22.04|2027-06-01|2032-04-21"
    "ubuntu:22.10|2023-07-20|2023-07-20"
    "ubuntu:23.04|2024-01-20|2024-01-20"
    "ubuntu:23.10|2024-07-12|2024-07-12"
    "ubuntu:24.04|2029-05-31|2034-04-25"
    "ubuntu:24.10|2025-07-10|2025-07-10"
    "ubuntu:25.04|2026-01-17|2026-01-17"
    "ubuntu:25.10|2026-07-01|2026-07-01"
    "ubuntu:26.04|2031-05-29|2036-04-23"
)
# END EOL TABLE

# =============================================================================
# SYSTEM RESTART CHECK
# =============================================================================

# Today's date as YYYY-MM-DD. A function so tests can pin it.
today_iso() {
    date +%Y-%m-%d
}

# Days since 1970-01-01 for a YYYY-MM-DD date (proleptic Gregorian). Pure
# arithmetic, so it needs neither GNU `date -d` nor any other tool.
date_to_days() {
    local y=$((10#${1:0:4})) m=$((10#${1:5:2})) d=$((10#${1:8:2}))
    [[ $m -le 2 ]] && y=$((y - 1))
    local era=$((y / 400))
    local yoe=$((y - era * 400))
    local doy=$(((153 * ((m + 9) % 12) + 2) / 5 + d - 1))
    local doe=$((yoe * 365 + yoe / 4 - yoe / 100 + doy))
    echo $((era * 146097 + doe - 719468))
}

# Operating System Support Check. Running a release past its end of support
# means no security fixes; it is the most common serious finding on an older
# VPS. SUPPORT_END from os-release is used when the distribution provides it;
# otherwise the embedded EOL_TABLE (Ubuntu, Debian). Unknown releases are INFO,
# never a guess.
check_os_support() {
    should_run_check "system" || return 0

    local std="" ext="" se entry key row_std row_ext
    se=$(sed -n 's/^SUPPORT_END=//p' "$OS_RELEASE_FILE" 2>/dev/null | tr -d "\"'" | head -n 1)
    if [[ "$se" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
        std="$se"
        ext="$se"
    else
        key="${OS_INFO[id]}:${OS_INFO[version]}"
        for entry in "${EOL_TABLE[@]}"; do
            IFS='|' read -r row_key row_std row_ext <<<"$entry"
            if [[ "$row_key" == "$key" ]]; then
                std="$row_std"
                ext="$row_ext"
                break
            fi
        done
    fi

    local name="${OS_INFO[name]:-this system}"
    if [[ -z "$std" ]]; then
        check_security "OS Support" "INFO" \
            "The end-of-support date of ${name} is not known to this script" \
            "Check your distribution's lifecycle page and plan an upgrade before support ends"
        return 0
    fi

    local today today_n std_n ext_n
    today="$(today_iso)"
    today_n=$(date_to_days "$today")
    std_n=$(date_to_days "$std")
    ext_n=$(date_to_days "$ext")

    local ext_label="extended support"
    [[ "${OS_INFO[id]}" == "ubuntu" ]] && ext_label="Ubuntu Pro (ESM)"
    [[ "${OS_INFO[id]}" == "debian" ]] && ext_label="Debian LTS"

    if [[ $today_n -gt $ext_n ]]; then
        check_security "OS Support" "FAIL" \
            "${name} reached end of support on ${ext} and no longer receives security updates" \
            "Move to a supported release (upgrade in place, or deploy a fresh server and migrate)" "true"
    elif [[ $today_n -gt $std_n ]]; then
        check_security "OS Support" "WARN" \
            "Standard support for ${name} ended on ${std}; security updates continue only through ${ext_label} until ${ext}" \
            "Plan an upgrade to a current release before ${ext}${OS_INFO[id]:+, or enable ${ext_label} meanwhile}"
    elif [[ $((std_n - today_n)) -le 90 ]]; then
        check_security "OS Support" "WARN" \
            "Support for ${name} ends on ${std} ($((std_n - today_n)) days)" \
            "Plan an upgrade to a current release before then"
    else
        check_security "OS Support" "PASS" "${name} is supported until ${std}" ""
    fi
}

# The newest installed kernel image that has the same flavour as the running
# one (the text after the last - or . in its release string: "generic",
# "amd64", "x86_64"), so rescue images and other flavours are ignored.
newest_installed_kernel() {
    local running="$1" flavour="${1##*[-.]}" f ver newest=""
    for f in "$BOOT_DIR"/vmlinuz-*; do
        [[ -e "$f" ]] || continue
        ver="${f##*/vmlinuz-}"
        [[ "${ver##*[-.]}" == "$flavour" ]] || continue
        newest="$(printf '%s\n%s\n' "$newest" "$ver" | sort -V | tail -n 1)"
    done
    printf '%s' "$newest"
}

# Does the system need a restart? Three independent signals: the distribution's
# own reboot-required marker, needs-restarting (RHEL family), and - for
# everyone, including Debian, which has no marker - a newer kernel in /boot than
# the one running.
check_system_restart() {
    should_run_check "system" || return 0

    local -a reasons=()
    [[ -f "$REBOOT_REQUIRED_FILE" ]] && reasons+=("the system reports that a restart is required")

    if command -v needs-restarting &>/dev/null && ! needs-restarting -r &>/dev/null; then
        reasons+=("needs-restarting reports that a restart is required")
    fi

    local running newest
    running=$(uname -r)
    newest=$(newest_installed_kernel "$running")
    if [[ -n "$newest" && "$newest" != "$running" ]] &&
        [[ "$(printf '%s\n%s\n' "$running" "$newest" | sort -V | tail -n 1)" == "$newest" ]]; then
        reasons+=("kernel $newest is installed but $running is running")
    fi

    if [[ ${#reasons[@]} -gt 0 ]]; then
        local msg
        msg=$(printf '%s; ' "${reasons[@]}")
        check_security "System Restart" "WARN" "A restart is pending: ${msg%; }" \
            "Reboot at a convenient time ('systemctl reboot') so security updates take effect"
    else
        check_security "System Restart" "PASS" "No restart is pending" ""
    fi
}

# =============================================================================
# ADDITIONAL SECURITY CHECKS
# =============================================================================

# MAC Status Check
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

# Evaluate a sysctl policy. Entries are "key|op|want[|fix]" where op is
#   ge    the value must be at least `want` (stricter values are fine)
#   eq    exactly `want`
#   mask  only the bits in `want` may be set (kernel.sysrq: 176 allows the
#         harmless sync/remount-ro/reboot keys)
# `fix` is the value to recommend when it differs from `want`. A parameter the
# kernel does not have cannot be configured, so it is left out of the score
# instead of being counted as insecure. Results:
#   SYSCTL_ASSESSED  parameters that could be read
#   SYSCTL_GOOD      how many of them meet the policy
#   SYSCTL_FIXES     "key = value" for each one that does not
sysctl_evaluate() {
    SYSCTL_ASSESSED=0
    SYSCTL_GOOD=0
    SYSCTL_FIXES=()
    local entry key op want fix actual ok
    for entry in "$@"; do
        IFS='|' read -r key op want fix <<<"$entry"
        actual=$(sysctl -n "$key" 2>/dev/null) || continue
        is_integer "$actual" || continue
        ((SYSCTL_ASSESSED++)) || true
        ok=false
        case "$op" in
            ge) [[ $actual -ge $want ]] && ok=true ;;
            mask) (((actual & ~want) == 0)) && ok=true ;;
            *) [[ $actual -eq $want ]] && ok=true ;;
        esac
        if [[ "$ok" == "true" ]]; then
            ((SYSCTL_GOOD++)) || true
        else
            SYSCTL_FIXES+=("$key = ${fix:-$want}")
        fi
    done
}

# Reverse-path filtering as the kernel applies it: an interface uses
# max(net.ipv4.conf.all, net.ipv4.conf.<iface>), and new interfaces take
# `default`. Reading only "all" misjudges RHEL-family systems, which leave all
# at 0 and set each interface to 1. Adds one result to the SYSCTL_* totals.
sysctl_evaluate_rp_filter() {
    local all default
    all=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null) || return 0
    default=$(sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null) || default=0
    is_integer "$all" || return 0
    is_integer "$default" || default=0
    ((SYSCTL_ASSESSED++)) || true

    local ok=true dir iface v effective
    effective=$((all > default ? all : default))
    [[ $effective -ge 1 ]] || ok=false
    for dir in "$IPV4_CONF_DIR"/*/; do
        iface="${dir%/}"
        iface="${iface##*/}"
        [[ "$iface" == "all" || "$iface" == "default" || "$iface" == "lo" ]] && continue
        [[ -r "${dir}rp_filter" ]] || continue
        v=$(cat "${dir}rp_filter" 2>/dev/null)
        is_integer "$v" || continue
        [[ $((v > all ? v : all)) -ge 1 ]] || ok=false
    done
    if [[ "$ok" == "true" ]]; then
        ((SYSCTL_GOOD++)) || true
    else
        SYSCTL_FIXES+=("net.ipv4.conf.all.rp_filter = 1")
    fi
}

# Shared verdict for the two sysctl checks.
# Usage: report_sysctl_result NAME PASS_MESSAGE_NOUN
report_sysctl_result() {
    local name="$1" noun="$2"
    local score="$SYSCTL_GOOD/$SYSCTL_ASSESSED"
    local fixes
    fixes="Add to /etc/sysctl.d/99-hardening.conf, then run 'sysctl --system': $(printf '%s; ' "${SYSCTL_FIXES[@]}")"
    fixes="${fixes%; }"
    if [[ $SYSCTL_ASSESSED -eq 0 ]]; then
        check_security "$name" "WARN" "Could not read any $noun setting (sysctl unavailable?)" ""
    elif [[ $SYSCTL_GOOD -eq $SYSCTL_ASSESSED ]]; then
        check_security "$name" "PASS" "All $noun settings are hardened ($score)" ""
    elif [[ $SYSCTL_GOOD -ge $((SYSCTL_ASSESSED / 2)) ]]; then
        check_security "$name" "WARN" "Partial $noun hardening ($score)" "$fixes"
    else
        check_security "$name" "FAIL" "Weak $noun hardening ($score)" "$fixes"
    fi
}

# Kernel Hardening Check
check_kernel_hardening() {
    should_run_check "kernel" || return 0

    sysctl_evaluate \
        "kernel.randomize_va_space|ge|2" \
        "net.ipv4.tcp_syncookies|ge|1" \
        "kernel.kptr_restrict|ge|1" \
        "kernel.dmesg_restrict|ge|1"
    sysctl_evaluate_rp_filter
    report_sysctl_result "Kernel Hardening" "kernel"
}

# True if a passwd(5) shell field gives an interactive login. An empty field
# means /bin/sh. nologin/false/sync/shutdown/halt are deliberate non-shells.
is_login_shell() {
    case "$1" in
        */nologin | */false | */sync | */shutdown | */halt) return 1 ;;
    esac
    return 0
}

# First regular-user UID (login.defs UID_MIN, default 1000).
get_uid_min() {
    local v
    v=$(awk '$1 == "UID_MIN" {print $2; exit}' "$LOGIN_DEFS" 2>/dev/null)
    is_numeric "$v" && echo "$v" || echo 1000
}

# User Account Auditing
# Reports: extra UID 0 accounts, accounts with an EMPTY password that can log
# in, and system accounts that have an interactive shell. Locked accounts
# ("!", "!!", "*" in /etc/shadow) are normal and are not "empty".
check_user_accounts() {
    should_run_check "users" || return 0

    local uid_min
    uid_min=$(get_uid_min)

    local -a uid0=() sys_login=() empty=()
    local -A can_login=()
    local name uid shell
    while IFS=: read -r name _ uid _ _ _ shell; do
        [[ -z "$name" || "$name" == \#* ]] && continue
        is_numeric "$uid" || continue
        is_login_shell "$shell" || continue
        can_login["$name"]=1
        if [[ $uid -eq 0 ]]; then
            [[ "$name" != "root" ]] && uid0+=("$name")
        elif [[ $uid -lt $uid_min ]]; then
            sys_login+=("$name")
        fi
    done <"$PASSWD_FILE"

    # A second UID 0 account is root by another name; it may also have a
    # non-login shell, so look at it regardless of is_login_shell above.
    local extra
    extra=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' "$PASSWD_FILE" 2>/dev/null | tr '\n' ' ')
    if [[ -n "$extra" ]]; then
        uid0=()
        read -ra uid0 <<<"$extra"
    fi

    local root_empty=false
    if [[ -r "$SHADOW_FILE" ]]; then
        while IFS=: read -r name hash _; do
            [[ -z "$name" ]] && continue
            [[ -z "$hash" && -n "${can_login[$name]+x}" ]] || continue
            empty+=("$name")
            [[ "$name" == "root" ]] && root_empty=true
        done <"$SHADOW_FILE"
    fi

    local -a problems=() recs=()
    local critical=false fail=false
    if [[ ${#uid0[@]} -gt 0 ]]; then
        problems+=("Extra UID 0 accounts: ${uid0[*]}")
        recs+=("Remove or re-number the extra UID 0 accounts; only root should have UID 0")
        critical=true
        fail=true
    fi
    if [[ ${#empty[@]} -gt 0 ]]; then
        problems+=("Accounts with an empty password: ${empty[*]}")
        recs+=("Lock each account ('passwd -l NAME') or give it a password")
        fail=true
        [[ "$root_empty" == "true" ]] && critical=true
    fi
    if [[ ${#sys_login[@]} -gt 0 ]]; then
        problems+=("System accounts with a login shell: ${sys_login[*]}")
        recs+=("Set the shell of service accounts to /usr/sbin/nologin")
    fi

    if [[ ${#problems[@]} -eq 0 ]]; then
        check_security "User Accounts" "PASS" "No user account issues found" ""
        return 0
    fi
    local msg rec
    msg=$(printf '%s; ' "${problems[@]}")
    rec=$(printf '%s; ' "${recs[@]}")
    if [[ "$fail" == "true" ]]; then
        check_security "User Accounts" "FAIL" "${msg%; }" "${rec%; }" "$critical"
    else
        check_security "User Accounts" "WARN" "${msg%; }" "${rec%; }"
    fi
}

# World-Writable Directories Check
# A world-writable directory without the sticky bit lets any local user delete
# or replace other users' files in it.
check_world_writable() {
    should_run_check "files" || return 0

    show_progress "Checking for world-writable directories"

    local ww_dirs=() mp dir
    while IFS= read -r mp; do
        [[ -d "$mp" ]] || continue
        while IFS= read -r dir; do
            ww_dirs+=("$dir")
        done < <(find_in_mount "$mp" -type d -perm -0002 ! -perm -1000 \
            ! -path /tmp ! -path /var/tmp ! -path /dev/shm -print)
    done < <(list_local_mountpoints)

    clear_progress

    local count=${#ww_dirs[@]}
    if [[ $count -eq 0 ]]; then
        check_security "World-Writable" "PASS" "No world-writable directories without the sticky bit" ""
    else
        local shown="${ww_dirs[*]:0:3}"
        local more=""
        [[ $count -gt 3 ]] && more=" (and $((count - 3)) more; see the report)"
        check_security "World-Writable" "WARN" \
            "Found $count world-writable $(plural "$count" directory directories) without the sticky bit: ${shown// /, }${more}" \
            "Remove world-write ('chmod o-w DIR') or add the sticky bit ('chmod +t DIR') unless the directory is meant to be shared"
        {
            echo "World-writable directories without the sticky bit:"
            printf '  %s\n' "${ww_dirs[@]}"
        } >>"$REPORT_FILE"
    fi
}

# Time Synchronization Check. "The NTP service is enabled" is not "the clock is
# synchronised" (systemd's NTPSynchronized property is the kernel's answer), so
# ask that first and use service detection only when it is unavailable.
check_time_sync() {
    should_run_check "time" || return 0

    local sync="" ntp_enabled=""
    if has_command timedatectl; then
        sync=$(timedatectl show --property=NTPSynchronized --value 2>/dev/null)
        ntp_enabled=$(timedatectl show --property=NTP --value 2>/dev/null)
    fi

    local svc active=""
    for svc in systemd-timesyncd chrony chronyd ntp ntpd ntpsec openntpd; do
        if service_is_active "$svc" 2>/dev/null; then
            active="$svc"
            break
        fi
    done

    if [[ "$sync" == "yes" ]]; then
        check_security "Time Sync" "PASS" "The clock is synchronised${active:+ ($active)}" ""
    elif [[ "$sync" == "no" && (-n "$active" || "$ntp_enabled" == "yes") ]]; then
        check_security "Time Sync" "WARN" "${active:-NTP} is enabled but the clock is not synchronised" \
            "Check the time service ('timedatectl status', 'chronyc tracking') and that outbound NTP (UDP 123) is allowed"
    elif [[ -n "$active" ]]; then
        check_security "Time Sync" "PASS" "Time synchronization service is active ($active)" ""
    elif [[ "$ntp_enabled" == "yes" ]]; then
        check_security "Time Sync" "PASS" "Time synchronization is enabled (timedatectl)" ""
    else
        check_security "Time Sync" "WARN" "No time synchronization detected" \
            "Install and enable chrony ('apt install chrony') or systemd-timesyncd"
    fi
}

# Audit System Check. auditd is valuable but is a Level 2 control (CIS) and
# heavy on small servers. Installed-but-stopped is INFO too: on some systems
# (Arch) the package is a dependency of core libraries and nobody chose it. A
# daemon that IS running without rules is a real gap.
check_audit_system() {
    should_run_check "audit" || return 0

    if pkg_installed auditd || pkg_installed audit; then
        if service_is_active auditd; then
            local rule_count=0
            if command -v auditctl &>/dev/null; then
                rule_count=$(auditctl -l 2>/dev/null | grep -c "^-" || true)
            fi
            if [[ $rule_count -gt 0 ]]; then
                check_security "Audit System" "PASS" "auditd is running with $rule_count $(plural "$rule_count" rule rules)" ""
            else
                check_security "Audit System" "WARN" "auditd is running but has no rules" \
                    "Add audit rules (e.g. copy /usr/share/doc/auditd/examples/rules/ to /etc/audit/rules.d/)"
            fi
        else
            check_security "Audit System" "INFO" "auditd is installed but not running" \
                "Optional: enable it ('systemctl enable --now auditd') if you want an audit trail"
        fi
    else
        check_security "Audit System" "INFO" "auditd is not installed" \
            "Optional: install auditd for a security audit trail ('apt install auditd')"
    fi
}

check_core_dumps() {
    should_run_check "core" || return 0

    local core_disabled=false
    local detail=""

    # 1. Hard ulimit of 0 (cannot be raised by a process).
    local core_limit
    core_limit=$(ulimit -Hc 2>/dev/null || echo "unknown")
    if [[ "$core_limit" == "0" ]]; then
        core_disabled=true
        detail="ulimit"
    fi

    # 2. "<domain> hard core 0" in limits.conf or any limits.d drop-in.
    local limit_files=("$LIMITS_CONF") lf
    if [[ -d "$LIMITS_D" ]]; then
        for lf in "$LIMITS_D"/*.conf; do
            [[ -f "$lf" ]] && limit_files+=("$lf")
        done
    fi
    if grep -qhE "^[[:space:]]*[^#[:space:]]+[[:space:]]+hard[[:space:]]+core[[:space:]]+0([[:space:]]|$)" \
        "${limit_files[@]}" 2>/dev/null; then
        core_disabled=true
        detail="${detail:+$detail, }limits.conf"
    fi

    # 3. systemd-coredump configured not to store dumps, in coredump.conf or
    #    any coredump.conf.d drop-in.
    local cf coredump_files=("$COREDUMP_CONF")
    if [[ -d "$COREDUMP_CONF_D" ]]; then
        for cf in "$COREDUMP_CONF_D"/*.conf; do
            [[ -f "$cf" ]] && coredump_files+=("$cf")
        done
    fi
    if grep -qhE "^[[:space:]]*(Storage[[:space:]]*=[[:space:]]*none|ProcessSizeMax[[:space:]]*=[[:space:]]*0)" \
        "${coredump_files[@]}" 2>/dev/null; then
        core_disabled=true
        detail="${detail:+$detail, }systemd-coredump"
    fi

    # fs.suid_dumpable=0 only stops SETUID programs from dumping. It is the
    # kernel default and does NOT restrict core dumps generally, so it must not
    # on its own produce a PASS.
    local suid_dumpable
    suid_dumpable=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "")

    if [[ "$core_disabled" == "true" ]]; then
        check_security "Core Dumps" "PASS" "Core dumps are restricted (${detail})" ""
    elif [[ "$suid_dumpable" == "0" ]]; then
        check_security "Core Dumps" "WARN" \
            "Setuid dumps are disabled (suid_dumpable=0) but general core dumps are unrestricted" \
            "Add '* hard core 0' to /etc/security/limits.conf (or Storage=none in /etc/systemd/coredump.conf.d/)"
    else
        check_security "Core Dumps" "WARN" "Core dumps may be enabled" \
            "Disable core dumps to prevent sensitive data leakage ('* hard core 0' in limits.conf)"
    fi
}

# =============================================================================
# PRODUCTION HARDENING CHECKS
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
    done </etc/passwd

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "SSH Key Permissions" "PASS" "SSH directories have correct permissions" ""
    else
        local issue_count=${#issues[@]}
        check_security "SSH Key Permissions" "WARN" "Found $issue_count SSH permission $(plural "$issue_count" issue issues)" \
            "Fix SSH directory permissions: chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
    fi
}

# Cron Security Check. Cron can run anything as its owner, so who may use it
# matters: CIS wants /etc/cron.allow to exist (and cron.deny not to). An EMPTY
# cron.deny - what AlmaLinux and Rocky ship - restricts nobody.
check_cron_security() {
    should_run_check "cron" || return 0

    if ! has_command crontab; then
        check_security "Cron Security" "INFO" "Cron is not installed" ""
        return 0
    fi

    local -a issues=()
    local restricted=false
    [[ -f "$CRON_ALLOW" ]] && restricted=true
    [[ -s "$CRON_DENY" ]] && restricted=true

    local crondir perms
    for crondir in "${CRON_ETC_DIRS[@]}"; do
        if [[ -d "$crondir" ]]; then
            perms=$(portable_stat mode "$crondir")
            if [[ -n "$perms" ]] && [[ "${perms: -1}" =~ [2367] ]]; then
                issues+=("$crondir is world-writable")
            fi
        fi
    done

    # User crontabs are private files. The spool directory's own mode varies by
    # distribution (Debian 1730, RHEL 700, Alpine 755 with 600 files inside), so
    # what matters is that it is not world-writable and no crontab file is
    # readable by other users.
    local spool
    for spool in "${CRON_SPOOL_DIRS[@]}"; do
        [[ -d "$spool" ]] || continue
        perms=$(portable_stat mode "$spool")
        if [[ -n "$perms" ]] && [[ "${perms: -1}" =~ [2367] ]]; then
            issues+=("$spool is world-writable")
        fi
        if [[ -n "$(find "$spool" -maxdepth 1 -type f -perm -o+r 2>/dev/null | head -n 1)" ]]; then
            issues+=("a crontab file in $spool is readable by other users")
        fi
    done

    if [[ ${#issues[@]} -gt 0 ]]; then
        local msg
        msg=$(printf '%s; ' "${issues[@]}")
        check_security "Cron Security" "WARN" "${msg%; }" \
            "Fix the permissions: 'chmod o-w' on the cron directories, 'chmod 700 /var/spool/cron/crontabs'"
    elif [[ "$restricted" == "false" ]]; then
        check_security "Cron Security" "INFO" "Any user may use cron (no /etc/cron.allow, and cron.deny is absent or empty)" \
            "Optional: create /etc/cron.allow listing only the accounts that need cron ('echo root > /etc/cron.allow')"
    else
        check_security "Cron Security" "PASS" "Cron access is restricted and permissions are sound" ""
    fi
}

# Dangerous Network Protocols Check. dccp, sctp, rds and tipc are rarely needed
# and have a history of kernel flaws (CIS Level 2): loading one is a WARN,
# merely not blacklisting them is INFO.
check_dangerous_protocols() {
    should_run_check "kernel" || return 0

    local dangerous_protocols=("dccp" "sctp" "rds" "tipc")
    local loaded=() proto modules
    modules="$(lsmod 2>/dev/null)"
    for proto in "${dangerous_protocols[@]}"; do
        if grep -q "^$proto" <<<"$modules"; then
            loaded+=("$proto")
        fi
    done

    local blacklisted=0
    for proto in "${dangerous_protocols[@]}"; do
        if grep -rqE "install $proto /bin/(true|false)|blacklist $proto" "$MODPROBE_DIR" 2>/dev/null; then
            ((blacklisted++)) || true
        fi
    done

    if [[ ${#loaded[@]} -gt 0 ]]; then
        check_security "Network Protocols" "WARN" "Rarely needed protocols are loaded: ${loaded[*]}" \
            "Blacklist what you do not use: 'install ${loaded[0]} /bin/true' in /etc/modprobe.d/blacklist.conf"
    elif [[ $blacklisted -lt ${#dangerous_protocols[@]} ]]; then
        check_security "Network Protocols" "INFO" "Not loaded, but not blacklisted: ${dangerous_protocols[*]}" \
            "Optional: add 'install <protocol> /bin/true' to /etc/modprobe.d/blacklist.conf"
    else
        check_security "Network Protocols" "PASS" "Rarely needed network protocols are disabled" ""
    fi
}

# Login Banner Check. A warning banner is a legal/policy measure, not a
# technical defence, so its absence is INFO. The stock /etc/issue of every
# distribution only names the OS and kernel (with getty escapes such as \n \l
# \S \r \m), so "has text" cannot tell it apart from a real banner; a real
# banner says who may use the system or that use is monitored.
check_login_banner() {
    should_run_check "system" || return 0

    local has_banner=false
    local banner_words='authori[sz]ed|unauthori[sz]ed|monitor|prohibit|permitted|restricted|private system|legal|consent|prosecut|warning|notice'

    local ssh_banner
    ssh_banner=$(get_ssh_config "Banner" "none")
    if [[ "$ssh_banner" != "none" && -s "$ssh_banner" ]]; then
        has_banner=true
    fi

    if [[ -s "$ISSUE_FILE" ]] && grep -qiE "$banner_words" "$ISSUE_FILE" 2>/dev/null; then
        has_banner=true
    fi

    if [[ "$has_banner" == "true" ]]; then
        check_security "Login Banner" "PASS" "A login warning banner is configured" ""
    else
        check_security "Login Banner" "INFO" "No login warning banner is configured" \
            "Optional: add a usage notice to /etc/issue.net and set 'Banner /etc/issue.net' in sshd_config"
    fi
}

# Account Lockout Check. Locking accounts after repeated failures only matters
# where passwords can be tried, so it is INFO on a key-only server.
check_account_lockout() {
    should_run_check "password" || return 0

    local configured=false
    if grep -rqE '^[^#]*pam_(faillock|tally2)\.so' "$PAM_DIR" 2>/dev/null; then
        configured=true
    elif service_is_active fail2ban 2>/dev/null; then
        configured=true
    fi

    if [[ "$configured" == "true" ]]; then
        check_security "Account Lockout" "PASS" "Failed-login lockout is configured" ""
    elif ssh_password_login_possible; then
        check_security "Account Lockout" "WARN" "No account lockout policy while passwords are accepted" \
            "Configure pam_faillock, or install fail2ban, to slow password guessing"
    else
        check_security "Account Lockout" "INFO" "No account lockout policy (SSH is key-only)" ""
    fi
}

# Umask Settings Check. A default umask of 027 or stricter keeps new files from
# other users. Ubuntu keeps 022 but creates home directories 0750 (HOME_MODE),
# which achieves the same for user data, so that counts. Commented-out lines
# in the profile files do not.
check_umask_settings() {
    should_run_check "files" || return 0

    local secure=false umask_value home_mode f
    if [[ -f "$LOGIN_DEFS" ]]; then
        umask_value=$(awk '$1 == "UMASK" {print $2; exit}' "$LOGIN_DEFS" 2>/dev/null)
        home_mode=$(awk '$1 == "HOME_MODE" {print $2; exit}' "$LOGIN_DEFS" 2>/dev/null)
        if [[ "$umask_value" =~ ^[0-7]+$ ]] && (((8#$umask_value & 8#027) == 8#027)); then
            secure=true
        fi
        if [[ "$home_mode" =~ ^[0-7]+$ ]] && (((8#$home_mode & 8#007) == 0)); then
            secure=true
        fi
    fi
    for f in "${PROFILE_FILES[@]}"; do
        [[ -f "$f" ]] || continue
        if grep -qE '^[[:space:]]*umask[[:space:]]+0?(27|37|77)([[:space:]]|$)' "$f" 2>/dev/null; then
            secure=true
        fi
    done

    if [[ "$secure" == "true" ]]; then
        check_security "Umask Settings" "PASS" "New files are private to the owner and group" ""
    else
        check_security "Umask Settings" "INFO" "The default umask (${umask_value:-022}) lets other users read new files" \
            "Optional: set UMASK 027 in /etc/login.defs"
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
        check_security "Log Permissions" "WARN" "Found ${#issues[@]} log permission $(plural "${#issues[@]}" issue issues)" \
            "Restrict log file permissions (chmod 640 for sensitive logs)"
    fi
}

# Secure Boot / Bootloader Check. Informational: most VPS platforms cannot
# enable Secure Boot, and a GRUB password is bypassed by the hypervisor console.
check_secure_boot() {
    should_run_check "system" || return 0

    if [[ -d "$EFI_DIR" ]]; then
        local status="unknown" sb_file sb_value
        for sb_file in "$EFI_DIR"/efivars/SecureBoot-*; do
            if [[ -f "$sb_file" ]]; then
                sb_value=$(od -An -t u1 "$sb_file" 2>/dev/null | awk '{print $NF}')
                [[ "$sb_value" == "1" ]] && status="enabled" || status="disabled"
                break
            fi
        done
        if command -v mokutil &>/dev/null && mokutil --sb-state 2>/dev/null | grep -i "SecureBoot enabled" >/dev/null; then
            status="enabled"
        fi
        case "$status" in
            enabled) check_security "Secure Boot" "PASS" "UEFI Secure Boot is enabled" "" ;;
            disabled) check_security "Secure Boot" "INFO" "UEFI Secure Boot is disabled" \
                "Optional: enable Secure Boot if your provider supports it" ;;
            *) check_security "Secure Boot" "INFO" "Secure Boot status could not be determined" "" ;;
        esac
    elif [[ -f /boot/grub/grub.cfg || -f /boot/grub2/grub.cfg ]]; then
        if grep -qE "password|set superusers" /etc/grub.d/* 2>/dev/null; then
            check_security "Bootloader Security" "PASS" "A GRUB password is configured" ""
        else
            check_security "Bootloader Security" "INFO" "No GRUB password is configured" \
                "Optional: set a GRUB password (only meaningful if others can reach the console)"
        fi
    fi
}

# Process Accounting Check. Optional command auditing; not a baseline control.
check_process_accounting() {
    should_run_check "audit" || return 0

    local accounting_enabled=false

    if pkg_installed psacct || pkg_installed acct; then
        if service_is_active psacct 2>/dev/null || service_is_active acct 2>/dev/null; then
            accounting_enabled=true
        fi
    fi
    if command -v lastcomm &>/dev/null && [[ -n "$(lastcomm 2>/dev/null | head -n 1)" ]]; then
        accounting_enabled=true
    fi

    if [[ "$accounting_enabled" == "true" ]]; then
        check_security "Process Accounting" "PASS" "Process accounting is enabled" ""
    else
        check_security "Process Accounting" "INFO" "Process accounting is not enabled" \
            "Optional: install and enable psacct/acct to record every command run"
    fi
}

# IPv6 Security Check. A host with a global IPv6 address is reachable over IPv6
# regardless of how well its IPv4 firewall is configured, so IPv6 needs its own
# default-deny policy. The kernel's own address table is read (no iproute2
# needed); native nftables rulesets are understood, not just ip6tables rules.
check_ipv6_security() {
    should_run_check "network" || return 0

    if [[ ! -e "$PROC_IPV6_DISABLE" ]] || [[ "$(cat "$PROC_IPV6_DISABLE" 2>/dev/null)" == "1" ]]; then
        check_security "IPv6 Security" "PASS" "IPv6 is disabled" ""
        return 0
    fi

    # /proc/net/if_inet6 column 4 is the address scope; 00 = global.
    if ! awk '$4 == "00" {found = 1} END {exit !found}' "$PROC_IF_INET6" 2>/dev/null; then
        check_security "IPv6 Security" "PASS" \
            "IPv6 is enabled but has no global address, so the server is not reachable over IPv6" ""
        return 0
    fi

    local protected=false
    if ufw_is_protecting; then
        # UFW only manages IPv6 rules when IPV6=yes (or the file is absent).
        if [[ ! -r "$UFW_DEFAULTS" ]] || grep -qiE '^[[:space:]]*IPV6=yes' "$UFW_DEFAULTS" 2>/dev/null; then
            protected=true
        fi
    fi
    firewalld_is_running && protected=true
    if [[ "$protected" == "false" ]] && has_command nft &&
        nft list ruleset 2>/dev/null | nft_input_default_deny "ip6|inet"; then
        protected=true
    fi
    if [[ "$protected" == "false" ]] && has_command ip6tables && iptables_input_default_deny ip6tables; then
        protected=true
    fi

    if [[ "$protected" == "true" ]]; then
        check_security "IPv6 Security" "PASS" "IPv6 is reachable and inbound IPv6 traffic is default-denied" ""
    else
        check_security "IPv6 Security" "WARN" \
            "IPv6 is reachable but no default-deny IPv6 firewall policy was found" \
            "Enable IPv6 in your firewall ('IPV6=yes' in /etc/default/ufw, then 'ufw reload'), or disable IPv6 with 'net.ipv6.conf.all.disable_ipv6 = 1'"
    fi
}

# Wireless Interface Check (for servers)
check_wireless_interfaces() {
    should_run_check "network" || return 0

    local wireless_count=0

    # Check for wireless interfaces
    if command -v iw &>/dev/null; then
        wireless_count=$(iw dev 2>/dev/null | grep -c "Interface" || true)
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
        check_security "Wireless Interfaces" "WARN" "Found $wireless_count wireless $(plural "$wireless_count" interface interfaces)" \
            "Disable wireless interfaces on production servers if not needed"
    fi
}

# USB Storage Restriction Check. A virtual server has no USB bus, so there is
# nothing to restrict; on hardware it is optional hardening.
check_usb_storage() {
    should_run_check "system" || return 0

    if [[ ! -d "$USB_BUS_DIR" ]]; then
        check_security "USB Storage" "PASS" "No USB bus present (virtual server)" ""
        return 0
    fi

    local usb_disabled=false usb_loaded=false
    if grep -rqE "blacklist usb-storage|install usb-storage /bin/(true|false)" "$MODPROBE_DIR" 2>/dev/null; then
        usb_disabled=true
    fi
    if lsmod 2>/dev/null | grep "usb_storage" >/dev/null; then
        usb_loaded=true
    fi

    if [[ "$usb_disabled" == "true" && "$usb_loaded" == "false" ]]; then
        check_security "USB Storage" "PASS" "USB storage is disabled" ""
    else
        check_security "USB Storage" "INFO" "USB storage is not restricted" \
            "Optional on hardware: add 'blacklist usb-storage' to /etc/modprobe.d/blacklist.conf"
    fi
}

# Compiler Access Check. Build toolchains on a production server make
# post-exploitation easier, but plenty of servers build things: INFO, not a failure.
check_compiler_access() {
    should_run_check "system" || return 0

    # Only real compilers. Deliberately excludes `as`/`ld` (binutils, present on
    # almost every system) and `make` (a build tool, not a compiler).
    local compilers=("gcc" "g++" "cc" "clang" "tcc")
    local found_compilers=() compiler

    for compiler in "${compilers[@]}"; do
        if command -v "$compiler" &>/dev/null; then
            found_compilers+=("$compiler")
        fi
    done

    if [[ ${#found_compilers[@]} -eq 0 ]]; then
        check_security "Compiler Access" "PASS" "No compilers installed" ""
    else
        check_security "Compiler Access" "INFO" "$(plural "${#found_compilers[@]}" Compiler Compilers) installed: ${found_compilers[*]}" \
            "Optional: remove build toolchains from a production server you do not build on"
    fi
}

# Public IP Check
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
# ADVANCED SECURITY CHECKS
# =============================================================================

# Extended SSH hardening. Only settings whose value can actually be wrong are
# scored: awarding a point for each setting that merely sits at a safe default
# made a stock sshd_config look "poorly hardened". Optional extras (X11, idle
# timeout, AllowUsers) are reported separately as INFO.
check_ssh_hardening_extended() {
    should_run_check "ssh" || return 0

    local -a issues=() fixes=() hints=()
    local failed=false

    # Accounts with an empty password must never be able to log in over SSH.
    local permit_empty
    permit_empty=$(get_ssh_config "PermitEmptyPasswords" "no")
    if [[ "$permit_empty" == "yes" ]]; then
        issues+=("PermitEmptyPasswords is yes")
        fixes+=("PermitEmptyPasswords no")
        failed=true
    fi

    # Explicitly enabled legacy ciphers (the default list contains none).
    local ciphers weak_cipher found=""
    ciphers=$(get_ssh_config "Ciphers" "")
    for weak_cipher in arcfour 3des-cbc blowfish-cbc cast128-cbc aes128-cbc aes192-cbc aes256-cbc; do
        [[ ",$ciphers," == *",$weak_cipher,"* ]] && found+="${found:+, }$weak_cipher"
    done
    if [[ -n "$found" ]]; then
        issues+=("weak ciphers enabled: $found")
        fixes+=("remove $found from Ciphers")
    fi

    local pubkey
    pubkey=$(get_ssh_config "PubkeyAuthentication" "yes")
    if [[ "$pubkey" != "yes" ]]; then
        issues+=("PubkeyAuthentication is $pubkey")
        fixes+=("PubkeyAuthentication yes")
    fi

    # OpenSSH's default is 6; going above it only helps a guessing attacker.
    local tries
    tries=$(get_ssh_config "MaxAuthTries" "6")
    if is_numeric "$tries" && [[ $tries -gt 6 ]]; then
        issues+=("MaxAuthTries is $tries")
        fixes+=("MaxAuthTries 4")
    elif is_numeric "$tries" && [[ $tries -gt 4 ]]; then
        hints+=("MaxAuthTries $tries (CIS suggests 4)")
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "SSH Hardening" "PASS" "No weak SSH settings found" ""
    else
        local msg rec
        msg=$(printf '%s; ' "${issues[@]}")
        rec="In /etc/ssh/sshd_config set: $(printf '%s; ' "${fixes[@]}")"
        if [[ "$failed" == "true" ]]; then
            check_security "SSH Hardening" "FAIL" "${msg%; }" "${rec%; }"
        else
            check_security "SSH Hardening" "WARN" "${msg%; }" "${rec%; }"
        fi
    fi

    # Optional extras: useful, but not a failure on a correctly run server.
    local x11 alive count users groups
    x11=$(get_ssh_config "X11Forwarding" "no")
    alive=$(get_ssh_config "ClientAliveInterval" "0")
    count=$(get_ssh_config "ClientAliveCountMax" "3")
    users=$(get_ssh_config "AllowUsers" "")
    groups=$(get_ssh_config "AllowGroups" "")
    [[ "$x11" == "yes" ]] && hints+=("X11Forwarding is on")
    if [[ "$alive" == "0" || "$count" == "0" ]]; then
        hints+=("no idle-session timeout (ClientAliveInterval ${alive}, ClientAliveCountMax ${count})")
    fi
    [[ -z "$users" && -z "$groups" ]] && hints+=("no AllowUsers/AllowGroups limit")
    if [[ ${#hints[@]} -gt 0 ]]; then
        local hint_msg
        hint_msg=$(printf '%s; ' "${hints[@]}")
        check_security "SSH Optional Hardening" "INFO" "${hint_msg%; }" \
            "Optional: X11Forwarding no; ClientAliveInterval 300 with ClientAliveCountMax 2; AllowUsers or AllowGroups for the accounts that need SSH"
    fi
}

# Sudoers Security Check. NOPASSWD is the default on cloud images and is
# reasonable with key-only SSH, so it is INFO; loose permissions on the sudoers
# file are a real problem. sudo-rs (Ubuntu 25.10+) reads /etc/sudoers-rs
# INSTEAD of /etc/sudoers when it exists, so that file is scanned too.
check_sudoers_security() {
    should_run_check "sudo" || return 0

    local -a files=() nopasswd=() perm_issues=()
    local f
    [[ -f "$SUDOERS_FILE" ]] && files+=("$SUDOERS_FILE")
    [[ -f "$SUDOERS_RS" ]] && files+=("$SUDOERS_RS")
    if [[ -d "$SUDOERS_DIR" ]]; then
        while IFS= read -r f; do
            files+=("$f")
        done < <(find "$SUDOERS_DIR" -maxdepth 1 -type f 2>/dev/null)
    fi

    local n
    for f in "${files[@]}"; do
        [[ -r "$f" ]] || continue
        n=$(grep -v '^[[:space:]]*#' "$f" 2>/dev/null | grep -c 'NOPASSWD' || true)
        [[ ${n:-0} -gt 0 ]] && nopasswd+=("${f##*/} ($n)")
    done

    local perms
    for f in "$SUDOERS_FILE" "$SUDOERS_RS"; do
        [[ -f "$f" ]] || continue
        perms=$(portable_stat mode "$f")
        # Unsafe if group/other can write it, or anyone outside the owner and
        # group can read it. 400, 440, 600 and 640 are all fine.
        if [[ -n "$perms" ]] && (((8#$perms & 8#022) != 0 || (8#$perms & 8#007) != 0)); then
            perm_issues+=("${f##*/} permissions are $perms (should be 440)")
        fi
    done

    if [[ ${#perm_issues[@]} -gt 0 ]]; then
        local msg
        msg=$(printf '%s; ' "${perm_issues[@]}")
        check_security "Sudoers Security" "WARN" "${msg%; }" "Run 'chmod 440 $SUDOERS_FILE'"
    elif [[ ${#nopasswd[@]} -gt 0 ]]; then
        local list
        list=$(printf '%s, ' "${nopasswd[@]}")
        check_security "Sudoers Security" "INFO" "Passwordless sudo (NOPASSWD) in: ${list%, }" \
            "NOPASSWD is the cloud-image default and reasonable with key-only SSH. If you remove it, first set a password for the account ('passwd USER') or you will lose sudo access"
    else
        check_security "Sudoers Security" "PASS" "Sudoers configuration looks sound" ""
    fi
}

# Temporary Filesystem Mount Options Check. nosuid and nodev matter wherever
# users can write; noexec is stronger but breaks some installers. systemd
# mounts /dev/shm nosuid,nodev and leaves /tmp on the root filesystem, so
# requiring everything everywhere warned on every stock server: a missing
# nosuid/nodev on a MOUNTED temp filesystem is a WARN, the rest is INFO.
check_tmp_mount_options() {
    should_run_check "mounts" || return 0

    local -a warn=() hints=()
    local mountpoint opts opt
    for mountpoint in /tmp /dev/shm /var/tmp; do
        [[ -d "$mountpoint" ]] || continue
        opts=$(awk -v mp="$mountpoint" '$2 == mp {o = $4} END {print o}' "$PROC_MOUNTS" 2>/dev/null)
        if [[ -z "$opts" ]]; then
            hints+=("$mountpoint is not a separate mount")
            continue
        fi
        for opt in nosuid nodev; do
            [[ ",$opts," == *",$opt,"* ]] || warn+=("$mountpoint lacks $opt")
        done
        [[ ",$opts," == *",noexec,"* ]] || hints+=("$mountpoint lacks noexec")
    done

    if [[ ${#warn[@]} -gt 0 ]]; then
        local msg
        msg=$(printf '%s; ' "${warn[@]}")
        check_security "Temp Mount Options" "WARN" "${msg%; }" \
            "Add nosuid,nodev (and noexec where compatible) to the mount options in /etc/fstab, then remount"
    elif [[ ${#hints[@]} -gt 0 ]]; then
        local hint_msg
        hint_msg=$(printf '%s; ' "${hints[@]}")
        check_security "Temp Mount Options" "INFO" "${hint_msg%; }" \
            "Optional: mount /tmp (and /var/tmp) with nosuid,nodev,noexec, e.g. 'tmpfs /tmp tmpfs defaults,nosuid,nodev,noexec 0 0' in /etc/fstab"
    else
        check_security "Temp Mount Options" "PASS" "Temporary filesystems are mounted with nosuid, nodev and noexec" ""
    fi
}

# File Integrity Monitoring Check. Presence only: an integrity database changes
# only when it is deliberately re-initialised, so its age says nothing about
# whether checks are being run.
check_file_integrity_monitoring() {
    should_run_check "integrity" || return 0

    local fim_name=""
    if command -v aide &>/dev/null || [[ -f /etc/aide.conf ]] || [[ -f /etc/aide/aide.conf ]]; then
        fim_name="AIDE"
    elif command -v tripwire &>/dev/null || [[ -f /etc/tripwire/tw.cfg ]]; then
        fim_name="Tripwire"
    elif command -v samhain &>/dev/null; then
        fim_name="samhain"
    elif command -v ossec-control &>/dev/null || [[ -d /var/ossec ]] || [[ -d /var/wazuh-agent ]]; then
        fim_name="OSSEC/Wazuh"
    fi

    if [[ -n "$fim_name" ]]; then
        check_security "File Integrity Monitoring" "PASS" "File integrity monitoring is installed ($fim_name)" ""
    else
        check_security "File Integrity Monitoring" "INFO" "No file integrity monitoring tool is installed" \
            "Optional: install AIDE ('apt install aide && aideinit') and schedule 'aide --check'"
    fi
}

# Rootkit Scanner Check. Informational only: these scanners are signature-based
# and rarely updated, so a missing one is not a finding.
check_rootkit_detection() {
    should_run_check "integrity" || return 0

    if command -v rkhunter &>/dev/null; then
        check_security "Rootkit Detection" "PASS" "A rootkit scanner is installed (rkhunter)" ""
    elif command -v chkrootkit &>/dev/null; then
        check_security "Rootkit Detection" "PASS" "A rootkit scanner is installed (chkrootkit)" ""
    else
        check_security "Rootkit Detection" "INFO" "No rootkit scanner is installed" ""
    fi
}

# Legacy / Plaintext Service Check. telnet, rsh, rlogin, rexec, finger, tftp and
# talk send credentials (or data) in cleartext. A service is a finding only if
# something is LISTENING on its port: distributions ship these server binaries
# inside general packages (Arch's inetutils, installed to provide `hostname`),
# so their presence alone says nothing.
check_legacy_services() {
    should_run_check "services" || return 0

    # protocol:port:name
    local -a legacy_ports=(
        tcp:23:telnet tcp:512:rexec tcp:513:rlogin tcp:514:rsh tcp:79:finger
        udp:69:tftp udp:517:talk udp:518:ntalk
    )

    local -a listening_public=() listening_local=()
    local have_ss=false
    local listen_output=""
    if has_command ss; then
        listen_output=$(ss -tuln 2>/dev/null) && have_ss=true
    elif has_command netstat; then
        listen_output=$(netstat -tuln 2>/dev/null) && have_ss=true
    fi
    if [[ "$have_ss" == "true" ]]; then
        local proto local_addr addr port entry want_proto want_port name
        while read -r proto local_addr; do
            port="${local_addr##*:}"
            addr="${local_addr%:*}"
            addr="${addr#\[}"
            addr="${addr%\]}"
            addr="${addr%%\%*}"
            for entry in "${legacy_ports[@]}"; do
                IFS=: read -r want_proto want_port name <<<"$entry"
                [[ "$proto" == "$want_proto"* && "$port" == "$want_port" ]] || continue
                if [[ "$(classify_bind_scope "$addr")" == "public" ]]; then
                    listening_public+=("$name ($port/$want_proto)")
                else
                    listening_local+=("$name ($port/$want_proto)")
                fi
            done
        done < <(printf '%s\n' "$listen_output" | awk '$1 ~ /^(tcp|udp)/ {print $1, ($5 ~ /:[0-9*]+$/) ? $5 : $4}')
    fi

    # Installed server software (binaries or packages), for the fallback and
    # for the "present but not listening" note.
    local -a installed=()
    local svc pkg
    for svc in telnetd in.telnetd rshd in.rshd rlogind in.rlogind rexecd in.rexecd \
        fingerd in.fingerd tftpd in.tftpd talkd in.talkd ntalkd; do
        command -v "$svc" &>/dev/null && installed+=("$svc")
    done
    for pkg in telnet-server inetutils-telnetd krb5-telnet rsh-server rsh-redone-server \
        finger-server efingerd tftp-server tftpd-hpa atftpd talk-server; do
        pkg_installed "$pkg" && installed+=("$pkg")
    done

    if [[ ${#listening_public[@]} -gt 0 ]]; then
        local msg="${listening_public[*]}"
        check_security "Legacy Services" "FAIL" \
            "Plaintext services are listening on a public address: ${msg// /, }" \
            "Stop and remove them (use SSH/SFTP instead); they transmit credentials in cleartext" "true"
    elif [[ ${#listening_local[@]} -gt 0 ]]; then
        local msg="${listening_local[*]}"
        check_security "Legacy Services" "WARN" \
            "Plaintext services are listening on a local address: ${msg// /, }" \
            "Stop and remove them; use SSH/SFTP instead"
    elif [[ "$have_ss" == "true" ]]; then
        if [[ ${#installed[@]} -gt 0 ]]; then
            local msg="${installed[*]}"
            check_security "Legacy Services" "INFO" \
                "Legacy server software is installed but nothing is listening: ${msg// /, }" \
                "Optional: remove it if you do not need it"
        else
            check_security "Legacy Services" "PASS" "No legacy plaintext services are listening" ""
        fi
    elif [[ ${#installed[@]} -gt 0 ]]; then
        local msg="${installed[*]}"
        check_security "Legacy Services" "WARN" \
            "Legacy server software is installed (listeners could not be checked): ${msg// /, }" \
            "Remove it if unused - these services transmit credentials in cleartext"
    else
        check_security "Legacy Services" "PASS" "No legacy plaintext service software found" ""
    fi
}

check_sensitive_permissions() {
    should_run_check "files" || return 0

    local issues=() filepath perms world_bit

    # Files that must never be world-writable
    local no_world_write=(
        /etc/passwd /etc/shadow /etc/group /etc/gshadow
        /etc/sudoers /etc/crontab /etc/hosts /etc/fstab
        "$SSH_DIR/sshd_config" "$SSH_DIR/ssh_host_rsa_key"
        "$SSH_DIR/ssh_host_ed25519_key" "$SSH_DIR/ssh_host_ecdsa_key"
    )
    for filepath in "${no_world_write[@]}"; do
        [[ -f "$filepath" ]] || continue
        perms=$(portable_stat mode "$filepath")
        [[ -z "$perms" ]] && continue
        world_bit="${perms: -1}"
        if [[ "$world_bit" =~ [2367] ]]; then
            issues+=("$filepath world-writable (perms: $perms)")
        fi
    done

    # /etc/shadow and /etc/gshadow must never be world-readable
    for filepath in /etc/shadow /etc/gshadow; do
        [[ -f "$filepath" ]] || continue
        perms=$(portable_stat mode "$filepath")
        [[ -z "$perms" ]] && continue
        world_bit="${perms: -1}"
        if [[ "$world_bit" =~ [4567] ]]; then
            issues+=("$filepath is world-readable (perms: $perms)")
        fi
    done

    # SSH private host keys: 400 and 600 (root only) or 640 (root + ssh group)
    for filepath in "$SSH_DIR/ssh_host_rsa_key" "$SSH_DIR/ssh_host_ed25519_key" \
        "$SSH_DIR/ssh_host_ecdsa_key"; do
        [[ -f "$filepath" ]] || continue
        perms=$(portable_stat mode "$filepath")
        [[ -z "$perms" ]] && continue
        if [[ "$perms" != "400" && "$perms" != "600" && "$perms" != "640" ]]; then
            issues+=("$filepath: permissions $perms (should be 600)")
        fi
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "Sensitive File Perms" "PASS" \
            "Critical system files have secure permissions" ""
    else
        check_security "Sensitive File Perms" "FAIL" \
            "Found ${#issues[@]} insecure critical file $(plural "${#issues[@]}" permission permissions): ${issues[0]}" \
            "Fix: chmod 640 /etc/shadow; chmod 440 /etc/sudoers; chmod 600 $SSH_DIR/ssh_host_*_key"
    fi
}

# Docker daemon and container exposure. Docker publishes ports through its own
# iptables rules, which run BEFORE ufw/firewalld, so `ufw deny 8081` does not
# stop a container published on 0.0.0.0:8081 - the most common way a firewalled
# VPS ends up with an open database. Two results: daemon/container hygiene, and
# published ports.
check_docker_security() {
    should_run_check "docker" || return 0
    command -v docker &>/dev/null || return 0

    docker_daemon_security
    docker_published_ports
}

docker_daemon_security() {
    local issues=()

    # A world-accessible Docker socket is equivalent to passwordless root.
    if [[ -S /var/run/docker.sock ]]; then
        local sock_perms sock_uid
        sock_perms=$(portable_stat mode /var/run/docker.sock)
        sock_uid=$(portable_stat uid /var/run/docker.sock)
        if [[ -n "$sock_perms" && "${sock_perms: -1}" =~ [1-7] ]]; then
            issues+=("Docker socket is world-accessible (${sock_perms}), which grants root-equivalent access")
        fi
        if [[ -n "$sock_uid" && "$sock_uid" != "0" ]]; then
            issues+=("Docker socket is not owned by root (uid: $sock_uid)")
        fi
    fi

    if ! docker info &>/dev/null; then
        if [[ ${#issues[@]} -gt 0 ]]; then
            check_security "Docker Security" "WARN" "${issues[0]}" "Restrict the Docker socket permissions"
        else
            check_security "Docker Security" "INFO" "Docker is installed but the daemon is not running" ""
        fi
        return 0
    fi

    local container_ids privileged_count=0 cid is_priv
    container_ids=$(docker ps -q 2>/dev/null) || container_ids=""
    if [[ -n "$container_ids" ]]; then
        while IFS= read -r cid; do
            is_priv=$(docker inspect --format='{{.HostConfig.Privileged}}' "$cid" 2>/dev/null) || is_priv="false"
            [[ "$is_priv" == "true" ]] && ((privileged_count++)) || true
        done <<<"$container_ids"
        [[ $privileged_count -gt 0 ]] && issues+=("$privileged_count $(plural "$privileged_count" container containers) $(plural "$privileged_count" runs run) with --privileged")
    fi

    if docker info 2>/dev/null | grep -i "rootless" >/dev/null; then
        check_security "Docker Security" "PASS" "Docker is running in rootless mode" ""
    elif [[ ${#issues[@]} -eq 0 ]]; then
        check_security "Docker Security" "PASS" "No Docker daemon or container problems found" ""
    else
        check_security "Docker Security" "WARN" "${issues[0]}" \
            "Restrict the Docker socket permissions, avoid --privileged containers, and consider rootless mode"
    fi
}

docker_published_ports() {
    docker info &>/dev/null || return 0
    local ps_out
    ps_out=$(docker ps --format '{{.Names}}|{{.Ports}}' 2>/dev/null) || return 0

    local -A seen=()
    local -a exposed=()
    local name ports entry host addr port key
    while IFS='|' read -r name ports; do
        [[ -z "$name" ]] && continue
        local -a entries=()
        IFS=, read -ra entries <<<"$ports"
        for entry in "${entries[@]}"; do
            entry="${entry# }"
            [[ "$entry" == *"->"* ]] || continue
            host="${entry%%->*}"
            port="${host##*:}"
            addr="${host%:*}"
            addr="${addr#\[}"
            addr="${addr%\]}"
            [[ "$(classify_bind_scope "$addr")" == "public" ]] || continue
            # Web ports are normally published on purpose.
            [[ "$port" == "80" || "$port" == "443" ]] && continue
            key="$name:$port"
            [[ -n "${seen[$key]+x}" ]] && continue
            seen["$key"]=1
            exposed+=("$key")
        done
    done <<<"$ps_out"

    if [[ ${#exposed[@]} -eq 0 ]]; then
        check_security "Docker Published Ports" "PASS" "No container publishes a port to the internet (other than 80/443)" ""
        return 0
    fi
    local list="${exposed[*]}"
    list="${list// /, }"
    if ufw_is_protecting || firewalld_is_running; then
        check_security "Docker Published Ports" "WARN" \
            "Docker publishes these ports straight to the internet, bypassing ufw/firewalld: ${list}" \
            "Publish on loopback ('-p 127.0.0.1:PORT:PORT') behind a reverse proxy, or restrict them in the DOCKER-USER chain"
    else
        check_security "Docker Published Ports" "INFO" \
            "Containers publish these ports to the internet: ${list}" \
            "Publish only what must be public; use '-p 127.0.0.1:PORT:PORT' for the rest"
    fi
}

# Additional Network Sysctl Hardening Check
# Settings not covered by check_kernel_hardening(): source routing, ICMP
# redirects, sysrq, ptrace scope, forwarding.
check_network_sysctl() {
    should_run_check "kernel" || return 0

    local -a policy=(
        "net.ipv4.conf.all.accept_source_route|eq|0"
        "net.ipv4.conf.all.send_redirects|eq|0"
        "net.ipv4.conf.all.accept_redirects|eq|0"
        "net.ipv4.icmp_echo_ignore_broadcasts|eq|1"
        "net.ipv4.icmp_ignore_bogus_error_responses|eq|1"
        "kernel.sysrq|mask|176|0"
        "kernel.yama.ptrace_scope|ge|1"
    )
    # Packet forwarding is required by container runtimes and VPN/router
    # setups; telling those hosts to disable it would break them.
    if ! has_command docker && ! has_command podman && ! has_command wg &&
        ! has_command virsh && ! has_command lxc; then
        policy+=("net.ipv4.ip_forward|eq|0")
    fi

    sysctl_evaluate "${policy[@]}"
    report_sysctl_result "Network Sysctl" "network sysctl"
}

# Home Directory Permissions Check. A world-readable home exposes SSH keys, shell
# history and configuration. Only accounts that can log in are examined (a
# service account such as `nobody` has a nologin shell and no secrets).
check_home_directory_permissions() {
    should_run_check "users" || return 0

    local uid_min
    uid_min=$(get_uid_min)
    local -a issues=()
    local username uid homedir shell perms world_bit

    while IFS=: read -r username _ uid _ _ homedir shell; do
        is_numeric "$uid" || continue
        [[ $uid -lt $uid_min ]] && continue
        is_login_shell "$shell" || continue
        [[ -z "$homedir" || ! -d "$homedir" ]] && continue
        [[ "$homedir" == "/" || "$homedir" == "/dev/null" ]] && continue

        perms=$(portable_stat mode "$homedir")
        [[ -z "$perms" ]] && continue
        world_bit="${perms: -1}"
        if [[ "$world_bit" =~ [2367] ]]; then
            issues+=("$username ($perms, world-writable)")
        elif [[ "$world_bit" =~ [45] ]]; then
            # 4 = r--, 5 = r-x: world-readable. A bare 1 (--x) is traversal
            # only, so a hardened 711/751 home is not flagged.
            issues+=("$username ($perms)")
        fi
    done <"$PASSWD_FILE"

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "Home Dir Permissions" "PASS" "Home directories are not readable by other users" ""
    else
        local list="${issues[*]:0:5}"
        list="${list// (/ (}"
        check_security "Home Dir Permissions" "WARN" \
            "Home directories other users can read or write: ${list// $username/, $username}" \
            "Restrict them: 'chmod 750 /home/<user>' (or 700)"
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
        [[ "$line" =~ ^[[:space:]]*# || -z "${line// /}" ]] && continue

        if [[ "$line" == *"no_root_squash"* ]]; then
            issues+=("no_root_squash: ${line:0:80}")
        fi

        # Wildcard host spec: check each whitespace-separated token after the
        # path. Use `read -ra` (NOT `for token in $line`) so a bare `*` in an
        # export such as "/srv *(rw)" is NOT pathname-expanded against the
        # current directory - that would replace the `*` with local filenames
        # and hide the wildcard, producing a false-negative security result.
        local has_wildcard=false token
        local -a tokens=()
        read -ra tokens <<<"$line"
        for token in "${tokens[@]}"; do
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
    done </etc/exports

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "NFS Exports" "PASS" "NFS exports are securely configured" ""
    else
        check_security "NFS Exports" "WARN" \
            "Found ${#issues[@]} insecure NFS export $(plural "${#issues[@]}" option options): ${issues[0]}" \
            "Remove no_root_squash, wildcard exports, and 'insecure' from /etc/exports"
    fi
}

# PATH Security Check
# "." (or an empty entry) in PATH, or a world-writable directory in PATH, lets
# a local user plant a command that root later runs by name. This inspects the
# PATH the script was *started with* (ORIGINAL_PATH), because the script
# prepends trusted directories to its own PATH.
check_path_security() {
    should_run_check "system" || return 0

    local issues=()
    local -a path_entries=()
    # The sentinel keeps `read` from dropping a trailing empty field ("a:" means
    # "a" plus the current directory); the sentinel itself is discarded below.
    IFS=: read -ra path_entries <<<"${ORIGINAL_PATH:-}:sentinel"
    unset "path_entries[$((${#path_entries[@]} - 1))]"

    local entry perms world_bit
    for entry in "${path_entries[@]}"; do
        # Empty entry or literal "." both mean "current directory"
        if [[ -z "$entry" || "$entry" == "." ]]; then
            issues+=("PATH contains the current directory ('${entry:-empty entry}')")
            continue
        fi
        # World-writable directory in PATH (portable_stat follows symlinks)
        if [[ -d "$entry" ]]; then
            perms=$(portable_stat mode "$entry")
            [[ -z "$perms" ]] && continue
            world_bit="${perms: -1}"
            if [[ "$world_bit" =~ [2367] ]]; then
                issues+=("world-writable directory in PATH: $entry ($perms)")
            fi
        fi
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "PATH Security" "PASS" "No dangerous entries in the PATH this script was started with" ""
    else
        check_security "PATH Security" "FAIL" \
            "${issues[0]}" \
            "Remove '.', empty entries and world-writable directories from PATH (/etc/environment, /root/.bashrc, sudo secure_path)"
    fi
}

# Exposed Network Services Check. Databases, caches and cluster services are a
# top cause of VPS compromises when reachable from the internet. An address is
# "exposed" if classify_bind_scope calls it public: a wildcard bind OR a
# specific routable address (binding MySQL to the server's own public IP is
# just as open as 0.0.0.0).
check_exposed_services() {
    should_run_check "network" || return 0

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
        ["2375"]="Docker API (unauthenticated)"
    )

    local listen_output=""
    if has_command ss; then
        listen_output=$(ss -tuln 2>/dev/null) || listen_output=""
    elif has_command netstat; then
        listen_output=$(netstat -tuln 2>/dev/null) || listen_output=""
    fi
    [[ -z "$listen_output" ]] && return 0

    local -A seen=()
    local -a issues=()
    local critical=false
    local local_addr addr port
    while read -r local_addr; do
        port="${local_addr##*:}"
        addr="${local_addr%:*}"
        addr="${addr#\[}"
        addr="${addr%\]}"
        addr="${addr%%\%*}"
        [[ -n "${local_only_services[$port]+x}" ]] || continue
        [[ "$(classify_bind_scope "$addr")" == "public" ]] || continue
        [[ -n "${seen[$port]+x}" ]] && continue
        seen["$port"]=1
        issues+=("${local_only_services[$port]} (port $port on ${addr})")
        [[ "$port" == "2375" ]] && critical=true
    done < <(printf '%s\n' "$listen_output" | awk '$1 ~ /^(tcp|udp)/ {print ($5 ~ /:[0-9*]+$/) ? $5 : $4}')

    if [[ ${#issues[@]} -eq 0 ]]; then
        check_security "Exposed Services" "PASS" "No backend services are reachable from the internet" ""
    else
        local msg
        msg=$(printf '%s; ' "${issues[@]}")
        if [[ "$critical" == "true" || ${#issues[@]} -gt 1 ]]; then
            check_security "Exposed Services" "FAIL" "${msg%; }" \
                "Bind these to 127.0.0.1 (or a private address) and firewall them; an exposed Redis, MongoDB or Docker API is an immediate compromise" "$critical"
        else
            check_security "Exposed Services" "WARN" "${msg%; }" \
                "Bind it to 127.0.0.1 in the service configuration and keep a firewall rule as a second layer"
        fi
    fi
}

# =============================================================================
# SUMMARY AND RECOMMENDATIONS
# =============================================================================

REPORT_RULE="================================"

# One-line verdict for the summary. Wording follows the failures first (that is
# what needs action) and only then the score band, so "critical" is never
# claimed for a run with no critical failure, and "Excellent"/"Good" are never
# claimed while a FAIL is open.
# Usage: get_assessment SCORE CRITICAL_COUNT [FAIL_COUNT]
get_assessment() {
    local score="$1" critical="$2" fails="${3:-0}"
    if [[ $critical -gt 0 ]]; then
        echo "Critical issues found - fix the CRITICAL items first"
    elif [[ $fails -gt 0 && $score -ge 70 ]]; then
        echo "Mostly hardened, but some checks FAILED - fix those first"
    elif [[ $score -ge 90 ]]; then
        echo "Excellent - your server is well hardened"
    elif [[ $score -ge 70 ]]; then
        echo "Good - minor improvements recommended"
    elif [[ $score -ge 50 ]]; then
        echo "Fair - several issues need attention"
    else
        echo "Poor - many hardening gaps; work through the recommendations below"
    fi
}

print_summary() {
    local total=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))
    local duration
    duration=$(get_run_duration)

    output ""
    output "$REPORT_RULE"
    output "${BOLD}Audit Summary${NC}"
    output "$REPORT_RULE"
    output "${GREEN}PASS:${NC} $PASS_COUNT"
    output "${YELLOW}WARN:${NC} $WARN_COUNT"
    output "${RED}FAIL:${NC} $FAIL_COUNT"
    if [[ $CRITICAL_FAIL_COUNT -gt 0 ]]; then
        output "${RED}${BOLD}  of which CRITICAL:${NC} $CRITICAL_FAIL_COUNT"
    fi
    output "${BLUE}INFO:${NC} $INFO_COUNT ${GRAY}(not scored)${NC}"
    output ""
    output "Scored checks: $total"

    local score=0 assessment="" color="$GREEN"
    if [[ $total -gt 0 ]]; then
        score=$((PASS_COUNT * 100 / total))
        assessment="$(get_assessment "$score" "$CRITICAL_FAIL_COUNT" "$FAIL_COUNT")"
        if [[ $CRITICAL_FAIL_COUNT -gt 0 || $score -lt 50 ]]; then
            color="$RED"
        elif [[ $score -lt 90 || $FAIL_COUNT -gt 0 ]]; then
            color="$YELLOW"
        fi
        local score_text="Security Score: ${score}% (share of scored checks that passed)"
        local -a score_lines=() score_line
        mapfile -t score_lines < <(wrap_text "$TERM_COLS" 2 "$score_text")
        local score_head="Security Score: ${score}%"
        if [[ "${score_lines[0]}" == "$score_head"* ]]; then
            output "Security Score: ${BOLD}${score}%${NC}${GRAY}${score_lines[0]:${#score_head}}${NC}"
        else
            output "${score_lines[0]}"
        fi
        for score_line in "${score_lines[@]:1}"; do
            output "${GRAY}${score_line}${NC}"
        done
        output_wrapped "$color" 2 "Assessment: ${assessment}"
    fi
    output "${GRAY}Completed in ${duration}${NC}"

    {
        echo ""
        echo "$REPORT_RULE"
        echo "AUDIT SUMMARY"
        echo "$REPORT_RULE"
        echo "PASS: $PASS_COUNT"
        echo "WARN: $WARN_COUNT"
        echo "FAIL: $FAIL_COUNT"
        echo "CRITICAL FAIL: $CRITICAL_FAIL_COUNT"
        echo "INFO (not scored): $INFO_COUNT"
        echo "Scored checks: $total"
        if [[ $total -gt 0 ]]; then
            echo "Security Score: ${score}% (share of scored checks that passed)"
            echo "Assessment: ${assessment}"
        fi
        echo "Duration: $duration"
    } >>"$REPORT_FILE"
}

print_recommendations() {
    if [[ ${#RECOMMENDATIONS[@]} -eq 0 ]]; then
        output ""
        output "${GREEN}No recommendations - every check passed.${NC}"
        return
    fi

    local -a titles=("" "CRITICAL (fix immediately)" "HIGH PRIORITY" "MEDIUM PRIORITY" "LOW PRIORITY")
    local -a colors=("" "$RED" "$YELLOW" "$BLUE" "$GRAY")

    output ""
    output "$REPORT_RULE"
    output "${BOLD}Recommended Actions (priority order)${NC}"
    output "$REPORT_RULE"
    output ""
    output_wrapped "$GRAY" 0 "Fix these in order, critical items first:"
    {
        echo ""
        echo "$REPORT_RULE"
        echo "RECOMMENDED ACTIONS (PRIORITY ORDER)"
        echo "$REPORT_RULE"
    } >>"$REPORT_FILE"

    local n=1 p rec text line shown
    for p in 1 2 3 4; do
        shown=false
        for rec in "${RECOMMENDATIONS[@]}"; do
            [[ "${rec%%|*}" == "$p" ]] || continue
            text="$(printable "${rec#*|}")"
            if [[ "$shown" == "false" ]]; then
                shown=true
                output ""
                output "${colors[$p]}-- ${titles[$p]} --${NC}"
                printf '\n-- %s --\n' "${titles[$p]}" >>"$REPORT_FILE"
            fi
            local -a lines=()
            mapfile -t lines < <(wrap_text "$TERM_COLS" $((${#n} + 2)) "$n. $text")
            output "${colors[$p]}${lines[0]%% *}${NC} ${lines[0]#* }"
            for line in "${lines[@]:1}"; do
                output "$line"
            done
            printf '%s. %s\n' "$n" "$text" >>"$REPORT_FILE"
            ((n++))
        done
    done
}

# Print quick-start hardening guide for new VPS
print_quickstart_guide() {
    # A document, not a report line: wrap it even when piped (76 columns) and
    # keep it readable on a very wide terminal (at most 100). `local` makes
    # the width visible to output_wrapped for this call only.
    local TERM_COLS="$TERM_COLS"
    if [[ $TERM_COLS -le 0 ]]; then
        TERM_COLS=76
    elif [[ $TERM_COLS -gt 100 ]]; then
        TERM_COLS=100
    fi
    output ""
    output "$REPORT_RULE"
    output "${BOLD}Quick-Start Hardening Guide${NC}"
    output "$REPORT_RULE"
    output ""
    output_wrapped "" 0 "For a NEW VPS, complete these steps in order. Commands are for Debian/Ubuntu; on RHEL-family systems use dnf, firewalld and the 'wheel' group instead."
    output ""
    output_wrapped "${YELLOW}${BOLD}" 0 "Keep your current SSH session open while you change SSH or firewall settings, and confirm a second login works before closing it."
    output ""
    output_wrapped "$BOLD" 3 "1. Create a non-root user with sudo access:"
    output "   adduser yourusername"
    output "   usermod -aG sudo yourusername"
    output ""
    output_wrapped "$BOLD" 3 "2. Set up SSH key authentication (from your own computer):"
    output "   ssh-copy-id yourusername@your-server-ip"
    output ""
    output_wrapped "$BOLD" 3 "3. Disable root login and password auth:"
    output "   Create /etc/ssh/sshd_config.d/10-hardening.conf containing:"
    output "     PermitRootLogin no"
    output "     PasswordAuthentication no"
    output "   sshd -t && systemctl reload ssh"
    output ""
    output_wrapped "$BOLD" 3 "4. Enable a firewall (allow only SSH):"
    output "   ufw default deny incoming"
    output "   ufw default allow outgoing"
    output "   ufw allow ssh        # or: ufw allow <your-ssh-port>/tcp"
    output "   ufw enable"
    output ""
    output_wrapped "$BOLD" 3 "5. Install and enable fail2ban:"
    output "   apt install fail2ban"
    output "   systemctl enable --now fail2ban"
    output ""
    output_wrapped "$BOLD" 3 "6. Enable automatic security updates:"
    output "   apt install unattended-upgrades"
    output "   dpkg-reconfigure -plow unattended-upgrades"
    output ""
    output_wrapped "$GRAY" 0 "Run this script again after completing these steps."
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

# Where the report is, and what to do next. The path is kept in one piece so it
# can be copied: on a narrow terminal it moves to its own line.
print_closing_message() {
    output ""
    local saved="Audit complete. Report saved to: "
    if [[ $TERM_COLS -gt 0 && $((${#saved} + ${#REPORT_FILE})) -gt $TERM_COLS ]]; then
        output "Audit complete. Report saved to:"
        output "  ${BOLD}${REPORT_FILE}${NC}"
    else
        output "${saved}${BOLD}${REPORT_FILE}${NC}"
    fi

    # Provide helpful hints for new users
    if [[ $CRITICAL_FAIL_COUNT -gt 0 ]]; then
        output ""
        output "${RED}${BOLD}CRITICAL SECURITY ISSUES FOUND!${NC}"
        output_wrapped "" 0 "Your server has serious security vulnerabilities that need immediate attention."
        output ""
        output_wrapped "" 0 "For step-by-step hardening guidance, run:"
        output "  ${BOLD}sudo $0 --guide${NC}"
    elif [[ $FAIL_COUNT -gt 0 ]]; then
        output ""
        output_wrapped "$YELLOW" 0 "Security issues were found. Review the recommendations above."
    fi
}

main() {
    # Install cleanup trap now that a real run is starting (kept out of the
    # top level so the script stays safe to source for unit tests).
    trap cleanup EXIT INT TERM

    # Record the invocation for the report header (traceability/reproducibility).
    INVOCATION_ARGS="$*"

    # Check bash version first
    check_bash_version

    # Load configuration file(s) as DEFAULTS before parsing CLI arguments.
    # Precedence (lowest to highest): built-in defaults < config file < CLI flags.
    # Loading first guarantees command-line flags always override config values.
    load_config

    # Parse command line arguments (override config-file defaults; handles
    # --help/--version early exits before the root check).
    parse_args "$@"

    # Initialize colors and wrap width (after parsing args to respect
    # --quiet / --no-color)
    init_colors
    init_term_width

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

        local entry key desc
        for entry in "${CHECK_CATEGORIES[@]}"; do
            key="${entry%%|*}"
            desc="${entry#*|}"
            if [[ "${CONFIG[checks]}" == "all" ]] || [[ ",${CONFIG[checks]}," =~ ,$key, ]]; then
                output "  [x] $(printf '%-10s' "$key") $desc"
            else
                output "  [ ] $(printf '%-10s' "$key") $desc (skipped)"
            fi
        done

        exit 0
    fi

    # Check prerequisites (after colors so we can show warnings)
    check_prerequisites

    # Check root privileges
    check_root

    # Detect OS
    detect_os

    # Create secure report file
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
    output "${GRAY}Started $(date)${NC}"
    local prereq_note
    for prereq_note in "${PREREQ_NOTES[@]}"; do
        [[ "${CONFIG[quiet]}" == "true" ]] || notice "$YELLOW" NOTE "$prereq_note" >&2
    done

    # Write header to report, including run metadata so a saved report is
    # self-describing and reproducible (traceability).
    {
        echo "VPS Security Audit Tool v${VERSION}"
        echo "https://github.com/tomtom215/vps-audit"
        echo "Starting audit at $(date)"
        echo "================================"
        echo ""
        echo "System:          ${OS_INFO[name]}"
        echo "Kernel:          $(uname -r)"
        echo "Hostname:        $(hostname)"
        echo "Package manager: ${OS_INFO[pkg_manager]}"
        echo "Service manager: ${OS_INFO[service_manager]}"
        echo "Coreutils:       ${TOOL_INFO[coreutils]:-unknown}"
        echo "Invocation:      $0 ${INVOCATION_ARGS}"
        echo "Checks selected: ${CONFIG[checks]}"
        echo "Output format:   ${CONFIG[output_format]}"
        echo ""
    } >>"$REPORT_FILE"

    # System Information Section
    print_header "System Information"

    local hostname kernel_version uptime_info uptime_since public_ip
    local cpu_info cpu_cores total_mem total_disk load_avg

    hostname=$(get_display_hostname)
    kernel_version=$(uname -r)
    uptime_info=$(get_uptime)
    uptime_since=$(get_uptime_since)
    public_ip=$(get_public_ip)
    cpu_info=$(lscpu 2>/dev/null | grep "Model name" | cut -d':' -f2 | xargs || echo "Unknown")
    cpu_cores=$(get_cpu_cores || echo "Unknown")
    total_mem=$(get_memory_stats "total_human")
    total_disk=$(df -hP / 2>/dev/null | awk 'NR==2 {print $2}' || echo "Unknown")
    load_avg=$(get_load_average || echo "Unknown")

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

    echo "" >>"$REPORT_FILE"

    # Security Audit Section
    print_header "Security Audit Results"

    # Run all security checks
    check_system_restart
    check_os_support
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

    check_mac_status
    check_kernel_hardening
    check_user_accounts
    check_world_writable
    check_time_sync
    check_audit_system
    check_core_dumps

    # Production hardening checks
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

    # Advanced security checks
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
    } >>"$REPORT_FILE"

    print_closing_message

    # Exit with appropriate code
    if [[ $CRITICAL_FAIL_COUNT -gt 0 ]]; then
        exit 2
    elif [[ $FAIL_COUNT -gt 0 ]]; then
        exit 1
    else
        exit 0
    fi
}

# Run main() only when executed directly. When sourced (e.g. by the unit-test
# harness) the functions above are defined but no audit runs, enabling isolated
# testing of individual functions.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
