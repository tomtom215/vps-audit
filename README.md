# VPS Security Audit Script

A comprehensive Bash script for auditing the security and hardening of your VPS (Virtual Private Server). This tool performs 40+ security checks and provides a detailed report with prioritized recommendations for improvements.

**Perfect for new VPS setup** - Run this script right after receiving your server credentials to identify and fix security issues.

> **Fork Notice:** This is an actively maintained fork of [vernu/vps-audit](https://github.com/vernu/vps-audit). Versions 2.1.0+ include additional hardening checks, cross-platform compatibility improvements, and a comprehensive test suite. See [Changelog](#changelog) for details.

![Sample Output](./screenshot.png)

## Features

### Security Checks (40+)

#### SSH Configuration
- Root login status
- Password authentication
- Non-default port detection
- SSH key permissions (`.ssh` directories and `authorized_keys`)

#### Firewall & Network
- Firewall status (UFW, firewalld, iptables, nftables)
- Open ports detection (with public vs localhost categorization)
- IPv6 security (firewall rules when enabled)
- Dangerous network protocols (dccp, sctp, rds, tipc)
- Wireless interface detection (for servers)

#### Intrusion Prevention & Access Control
- Fail2ban, CrowdSec (native and Docker)
- Account lockout policy (pam_faillock/pam_tally2)
- Login warning banner configuration

#### System Updates
- Available system updates (with security update differentiation)
- Automatic updates (unattended-upgrades, dnf-automatic, yum-cron)

#### Authentication & Authorization
- Failed login attempts (journalctl and log file support)
- Password policy enforcement (pwquality checking)
- Sudo logging configuration (includes sudoers.d)
- User account auditing (UID 0, empty passwords, login shells)

#### File System Security
- SUID files detection (with extended whitelist)
- SGID files detection
- World-writable files/directories
- Log file permissions
- Umask settings
- Cron security (permissions and access control)

#### System Hardening
- Mandatory Access Control (SELinux, AppArmor)
- Kernel hardening (6 critical sysctl parameters)
- Core dump settings
- USB storage restrictions
- Secure Boot / GRUB password
- Compiler/development tools presence

#### Monitoring & Auditing
- Running services analysis
- Time synchronization (systemd-timesyncd, chronyd, ntpd)
- Audit system (auditd status and rules)
- Process accounting (psacct/acct)

### Performance Monitoring
- Disk space usage
- Memory usage
- CPU usage
- Load average

### Output Formats
- **Text Report** - Human-readable with color-coded results
- **JSON Report** - Machine-readable for automation and monitoring
- **Both** - Generate both formats simultaneously

## Requirements

- Linux system (multi-distro support)
- Root access or sudo privileges
- Bash 4.0+

### Supported Distributions

- **Debian/Ubuntu** family (Debian, Ubuntu, Mint, Pop!_OS, etc.)
- **RHEL/CentOS** family (RHEL, CentOS, Fedora, Rocky, Alma, etc.)
- **Arch** family (Arch, Manjaro, EndeavourOS)
- **SUSE** family (openSUSE, SLES)
- **Alpine** Linux

## Installation

1. Download the script:

```bash
wget https://raw.githubusercontent.com/tomtom215/vps-audit/main/vps-audit.sh
# or
curl -O https://raw.githubusercontent.com/tomtom215/vps-audit/main/vps-audit.sh
```

2. Make the script executable:

```bash
chmod +x vps-audit.sh
```

## Usage

Run the script with sudo privileges:

```bash
sudo ./vps-audit.sh
```

### Quick Start for New VPS

If you just received credentials for a new VPS, run:

```bash
# First, see what needs to be done
sudo ./vps-audit.sh

# For step-by-step hardening guidance
sudo ./vps-audit.sh --guide
```

### Command Line Options

```
Usage: ./vps-audit.sh [OPTIONS]

Options:
    -h, --help              Show help message
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
```

### Available Check Categories

| Category | Description |
|----------|-------------|
| ssh | SSH configuration (root login, password auth, port, key permissions) |
| firewall | Firewall status (UFW, firewalld, iptables, nftables) |
| ips | Intrusion prevention (fail2ban, crowdsec) |
| updates | System updates and auto-updates |
| logins | Failed login attempts |
| services | Running services analysis |
| ports | Open ports detection |
| resources | Disk, memory, CPU usage |
| sudo | Sudo logging configuration |
| password | Password policy and account lockout |
| suid | SUID/SGID file scanning |
| mac | SELinux/AppArmor status |
| kernel | Kernel hardening (sysctl settings) |
| users | User account auditing |
| files | File permissions (world-writable, logs, umask) |
| time | Time synchronization |
| audit | Audit daemon status |
| core | Core dump settings |
| cron | Cron security |
| network | Network protocols, IPv6, wireless |

### Examples

```bash
# Run all checks
sudo ./vps-audit.sh

# Show hardening guide for new VPS
sudo ./vps-audit.sh --guide

# Quiet mode with JSON output (for cron jobs)
sudo ./vps-audit.sh -q -f json

# Skip slow checks (SUID scan and network)
sudo ./vps-audit.sh --no-suid --no-network

# Custom thresholds
sudo ./vps-audit.sh --disk-warn 60 --disk-fail 90

# Run specific checks only
sudo ./vps-audit.sh --checks ssh,firewall,updates

# Preview what would run
sudo ./vps-audit.sh --dry-run
```

## Output Format

The script provides multiple output types:

### Console Output (color-coded)

```
[PASS] SSH Root Login - Root login is disabled
[WARN] SSH Port - Using standard port 22
[FAIL] Firewall Status - No firewall tool found
```

### Priority-Ordered Recommendations

Recommendations are automatically sorted by priority:
- **CRITICAL** - Fix immediately (e.g., root login enabled, no firewall)
- **HIGH** - Fix soon (e.g., password auth, missing updates)
- **MEDIUM** - Address when possible (e.g., SUID files, kernel settings)
- **LOW** - Nice to have (e.g., login banner, process accounting)

### JSON Report

Machine-readable format for integration with monitoring tools:

```json
{
  "version": "2.2.0",
  "timestamp": "2025-01-15T10:30:00+00:00",
  "hostname": "myserver",
  "os": "Ubuntu 24.04 LTS",
  "checks": [
    {"name": "SSH Root Login", "status": "PASS", "message": "Root login is disabled"},
    ...
  ],
  "summary": {"pass": 35, "warn": 5, "fail": 2, "critical_fail": 1}
}
```

## Exit Codes

- `0` - All checks passed (or only warnings)
- `1` - One or more checks failed
- `2` - Critical security issues found

## Thresholds

### Resource Usage Thresholds

| Level | Default |
|-------|---------|
| PASS  | < 50% usage |
| WARN  | 50-80% usage |
| FAIL  | > 80% usage |

### Security Thresholds

| Check | PASS | WARN | FAIL |
|-------|------|------|------|
| Failed Logins | < 10 | 10-50 | > 50 |
| Running Services | < 20 | 20-40 | > 40 |
| Open Ports | < 10 | 10-20 | > 20 |
| Public Ports | < 3 | 3-5 | > 5 |

## Configuration File

You can create a configuration file to set defaults:

**Locations (in order of precedence):**
1. `/etc/vps-audit.conf`
2. `~/.vps-audit.conf`
3. `./.vps-audit.conf`

**Example configuration:**

```bash
# /etc/vps-audit.conf
CONFIG[output_format]="both"
CONFIG[quiet]="false"
THRESHOLDS[disk_warn]=60
THRESHOLDS[disk_fail]=85
THRESHOLDS[failed_logins_warn]=20
```

**Note:** Configuration files are validated for security - they must be owned by root or the current user and must not be world-writable.

## Security Features

### Secure Report Files
- Reports are created with `600` permissions (owner read/write only)
- Uses `mktemp` for secure file creation
- Restrictive umask applied during execution

### Safe Execution
- Validates all inputs before use
- Secure configuration file validation (ownership/permissions checked)
- Proper error handling throughout
- Cleanup on interruption
- Prerequisites check before running

## Dependencies

### Core (required)
- `bash` >= 4.0
- `coreutils` (grep, awk, sed, cut, find, stat, etc.)

### Recommended
- `curl` - For public IP detection
- `ss` or `netstat` - For port scanning
- `sysctl` - For kernel parameter checking
- `journalctl` - For log analysis on systemd systems

### Optional (for specific checks)
- `docker` - Container security checks
- `ufw` / `firewall-cmd` / `iptables` - Firewall checks
- `auditctl` - Audit system checks
- `aa-status` - AppArmor checks
- `getenforce` - SELinux checks
- `mokutil` - Secure Boot status

## Best Practices

1. **Run immediately after VPS provisioning** - Identify issues before deployment
2. Run the audit regularly (e.g., weekly via cron)
3. Review the generated report thoroughly
4. Address any FAIL status immediately (especially CRITICAL)
5. Investigate WARN status during maintenance
6. Keep the script updated with your security policies

## Cron Job Example

```bash
# Run weekly audit with JSON output, email results
0 2 * * 0 /usr/local/bin/vps-audit.sh -q -f json -o /var/log/vps-audit/
```

## Limitations

- This is an **audit tool**, not an automatic hardening tool
- Some checks may need customization for specific environments
- Not a replacement for professional security audit
- Container-based checks require Docker daemon running

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Testing

This project includes a comprehensive test suite to ensure reliability across different Linux distributions.

### Running Integration Tests

```bash
# Run integration tests
./tests/integration-tests.sh
```

### Multi-Distribution Testing (Docker)

Test the script across multiple distributions using Docker:

```bash
# Test all supported distributions
./test-matrix.sh

# Test specific distributions
./test-matrix.sh ubuntu debian
./test-matrix.sh alpine

# List available distributions
./test-matrix.sh -l
```

Supported test distributions:
- Ubuntu 22.04, 24.04
- Debian 11, 12
- Rocky Linux 9
- AlmaLinux 9
- Fedora 39, 40
- Alpine 3.19, 3.20
- Arch Linux
- openSUSE Leap 15.5

## Changelog

### Version 2.2.0 (Fork)
- Added comprehensive command availability detection with caching
- Added portable stat wrapper (GNU vs BSD compatibility)
- Added tool version detection (busybox, GNU coreutils)
- Added multi-distribution Docker test matrix (12 distros)
- Added integration test suite (24 tests)
- Added GitHub Actions CI workflow
- Improved graceful degradation when optional commands are missing
- All scripts pass shellcheck with zero warnings

### Version 2.1.0 (Fork)
- Added 14 new production hardening checks:
  - SSH key permissions
  - SGID files scanning
  - Cron security
  - Dangerous network protocols
  - Login banner
  - Account lockout policy
  - Umask settings
  - Log file permissions
  - Secure Boot / GRUB password
  - Process accounting
  - IPv6 security
  - Wireless interface detection
  - USB storage restrictions
  - Compiler/development tools
- Added `--guide` option for quick-start hardening guidance
- Added priority-ordered recommendations (CRITICAL, HIGH, MEDIUM, LOW)
- Added security assessment scores
- Added Bash version check and prerequisites validation
- Improved config file security (ownership/permission validation)
- Improved JSON escaping for special characters
- Enhanced help/usage with check category documentation
- Added beginner-friendly assessment messages

### Version 2.0.0
- Complete refactoring with multi-distro support
- Added JSON output format
- Added command-line options and configuration files
- Added 8 new security checks (MAC, kernel hardening, user auditing, etc.)
- Fixed 78 identified issues from security audit
- Improved SSH configuration parsing
- Fixed iptables firewall detection
- Added proper exit codes
- Added summary statistics and recommendations
- Improved error handling and input validation
- Secure report file creation

## Security Notice

While this script helps identify common security issues, it should not be your only security measure. Always:

- Keep your system updated
- Monitor logs regularly
- Follow security best practices
- Consider professional security audits for critical systems

## Support

For support, please:

1. Check the existing issues
2. Create a new issue with detailed information
3. Provide the output of the script and your system information

Stay secure! 🔒
