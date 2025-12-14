# VPS Security Audit Script

A comprehensive Bash script for auditing the security and performance of your VPS (Virtual Private Server). This tool performs various security checks and provides a detailed report with recommendations for improvements.

![Sample Output](./screenshot.png)

## Features

### Security Checks

- **SSH Configuration**
  - Root login status
  - Password authentication
  - Non-default port usage
- **Firewall Status** (UFW, firewalld, iptables, nftables)
- **Intrusion Prevention** (Fail2ban, CrowdSec - native and Docker)
- **Failed Login Attempts** (with journalctl and log file support)
- **System Updates Status** (with security update differentiation)
- **Automatic Updates** (unattended-upgrades, dnf-automatic, yum-cron)
- **Running Services Analysis**
- **Open Ports Detection** (with public vs localhost categorization)
- **Sudo Logging Configuration** (includes sudoers.d checking)
- **Password Policy Enforcement** (comprehensive pwquality checking)
- **SUID Files Detection** (with expanded whitelist)
- **Mandatory Access Control** (SELinux, AppArmor)
- **Kernel Hardening** (sysctl security settings)
- **User Account Auditing** (UID 0, empty passwords, login shells)
- **World-Writable Files** (directories without sticky bit)
- **Time Synchronization** (systemd-timesyncd, chronyd, ntpd)
- **Audit System** (auditd status and rules)
- **Core Dump Settings**

### Performance Monitoring

- Disk Space Usage
- Memory Usage
- CPU Usage
- Load Average

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
wget https://raw.githubusercontent.com/vernu/vps-audit/main/vps-audit.sh
# or
curl -O https://raw.githubusercontent.com/vernu/vps-audit/main/vps-audit.sh
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

### Examples

```bash
# Run all checks
sudo ./vps-audit.sh

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

### Text Report

A detailed report file containing:
- All check results with status
- Specific recommendations for failed checks
- System resource usage statistics
- Timestamp of the audit

### JSON Report

Machine-readable format for integration with monitoring tools:

```json
{
  "version": "2.0.0",
  "timestamp": "2025-01-15T10:30:00+00:00",
  "hostname": "myserver",
  "os": "Ubuntu 24.04 LTS",
  "checks": [
    {"name": "SSH Root Login", "status": "PASS", "message": "Root login is disabled"},
    ...
  ],
  "summary": {"pass": 15, "warn": 5, "fail": 3, "critical_fail": 1}
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

## Security Features

### Secure Report Files

- Reports are created with `600` permissions (owner read/write only)
- Uses `mktemp` for secure file creation
- Restrictive umask applied during execution

### Safe Execution

- Validates all inputs before use
- Proper error handling throughout
- Cleanup on interruption

## Dependencies

### Core (required)

- `bash` >= 4.0
- `coreutils` (grep, awk, sed, cut, etc.)

### Recommended

- `curl` - For public IP detection
- `ss` or `netstat` - For port scanning
- `sysctl` - For kernel parameter checking

### Optional (for specific checks)

- `docker` - Container security checks
- `ufw` / `firewall-cmd` / `iptables` - Firewall checks
- `auditctl` - Audit system checks
- `aa-status` - AppArmor checks
- `getenforce` - SELinux checks
- `journalctl` - Log analysis on systemd systems

## Best Practices

1. Run the audit regularly (e.g., weekly via cron)
2. Review the generated report thoroughly
3. Address any FAIL status immediately
4. Investigate WARN status during maintenance
5. Keep the script updated with your security policies

## Cron Job Example

```bash
# Run weekly audit with JSON output, email results
0 2 * * 0 /usr/local/bin/vps-audit.sh -q -f json -o /var/log/vps-audit/
```

## Limitations

- Some checks may need customization for specific environments
- Not a replacement for professional security audit
- Container-based checks require Docker daemon running

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

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

Stay secure!
