# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). `vps-audit.sh --version` shows the
version; the `VERSION` constant in the script is the single source of truth.

## [2.5.0] - 2026-10-03

A correctness, accuracy and polish release. Each fix to the audit's behaviour
below has a regression test. **Behaviour changes that can affect scripts are
listed under "Changed".**

### Added
- **`INFO` status.** Results that are worth knowing but are not failures on a
  correctly run VPS are shown and never scored, and never change the exit code.
  The JSON summary gains `info`.
- **JSON report:** `schema_version` (1), and per check `category` and `priority`.
- **New checks:**
  - *OS Support* - warns before and fails after the end of support of the running
    Ubuntu or Debian release (embedded table, refreshed with
    `tools/update-eol-table.sh`) or any release whose `/etc/os-release` has
    `SUPPORT_END`.
  - *Docker Published Ports* - ports Docker publishes bypass UFW/firewalld.
  - *System Restart* now also detects a newer installed kernel than the one
    running (Debian has no `reboot-required` marker).
  - *SSH Optional Hardening* (INFO) for X11 forwarding, idle timeout and
    `AllowUsers`.
- **Options:** `--no-color`; `NO_COLOR` with any non-empty value and `TERM=dumb`
  now disable colour.
- **Input validation:** unknown `--checks` categories are rejected (previously a
  typo silently ran an empty audit that reported all-clear); percentage
  thresholds must be 1-100.
- **Output:** word-wrapped lines with hanging indents on a terminal, including
  notes, warnings, the system-information rows, the score and assessment, the
  closing messages and the `--guide` text (the guide also wraps at 76 columns
  when piped); the report path is kept in one piece; ASCII only.
- **Tests:** a behavioural suite (`tests/run.sh`) driven by stubbed commands and
  real captured fixtures; a distro and Bash-version matrix (`tests/matrix.sh`)
  that runs the suite, real-state scenarios (nftables rules, mounted
  filesystems, sshd) and a full audit inside a container per image. Bash 4.0 to
  4.3 run the full audit only (the harness needs 4.4). Their 48 verdicts matched
  Bash 5.3's apart from live memory and load values and the Alpine release each
  image ships; that is the evidence for the stated minimum version, Bash 4.0.
- **Project files:** `SECURITY.md`, issue forms (including "Wrong result"), a pull
  request template, `tools/update-eol-table.sh`.
- **Release workflow** that checks tag, version and changelog agree, runs the
  tests, and publishes the script with `SHA256SUMS` and a build-provenance
  attestation.

### Changed
- **Resource thresholds default to 80/90 percent** (disk and memory; were 50/80).
  Public-port thresholds are 6/11 and total-port thresholds 15/30 (were 3/5 and
  10/20). The `cpu_*` and `services_*` thresholds no longer exist; a config file
  that sets them is harmless.
- **Reported as `INFO` instead of `WARN`/`FAIL`:** CPU usage (a one-second sample),
  running-service count, Secure Boot / GRUB password, USB storage, compilers,
  process accounting, `auditd` absent, file-integrity and rootkit scanners
  absent, login banner, unrestricted cron, passwordless sudo, tmp mounts that are
  merely not separate, umask, rarely-used network protocols not blacklisted.
- **System Updates:** pending security updates are `FAIL` but no longer
  *critical*, so a fresh image on patch day does not exit 2.
- **Intrusion Prevention:** none installed is `WARN` while SSH accepts passwords
  and `INFO` when it is key-only (was `FAIL`). fail2ban must have a jail
  enabled; CrowdSec needs a firewall bouncer.
- **SSH Hardening** no longer awards points for settings that sit at a safe
  default, so a stock `sshd_config` is no longer "poorly hardened".
- **Password Policy** requires an active quality module and a minimum length of
  12; it no longer demands four character classes, and is `INFO` for key-only SSH.
- **Recommendation priority** follows the verdict (critical `FAIL`, other `FAIL`,
  `WARN`, low) instead of matching words in the check name and text.
- **Assessment wording** no longer says "Critical" without a critical failure,
  or "Excellent"/"Good" while a `FAIL` is open.
- **`--no-network`** now also keeps `dnf`, `yum` and `zypper` from refreshing
  repository metadata (it previously skipped only the public-IP lookup).
- **sysctl checks** accept stricter values, ignore parameters the kernel lacks,
  evaluate `rp_filter` as the kernel does, accept Ubuntu's `kernel.sysrq=176`, and
  skip `ip_forward` on container/VPN hosts. Recommendations state the wanted value.
- Check categories are defined once (`CHECK_CATEGORIES`) and drive `--checks`,
  `--help`, `--dry-run` and the README.
- Supported and tested releases brought up to date: Ubuntu 22.04, 24.04, 26.04;
  Debian 12, 13; Fedora 43, 44; Rocky and AlmaLinux 9, 10; Amazon Linux 2023;
  openSUSE Leap 16.0; Arch; Alpine 3.22-3.24. Fedora 39 and 40, Alpine 3.19 and
  3.20, openSUSE Leap 15.5 and Debian 11 (the old matrix) are no longer tested.
- CI rebuilt: pinned actions (full commit SHAs) and linters (hashes), least
  privilege, concurrency, `shfmt` enforced, and a single `CI OK` job that
  summarises the rest, to be used as the one required check. The release
  workflow is validated with `actionlint` but has not run yet: no tag has been
  pushed.
- Links to the project this one was derived from were removed from the script
  and the README. `LICENSE` is unchanged and keeps that project's copyright
  notice, as the MIT license requires.
- `tools/update-eol-table.sh` uses the endoflife.date v1 API; its output is
  identical to the old API's for the embedded table.
- `LICENSE`, public IP lookup behaviour and exit codes (0, 1, 2) are unchanged.

### Fixed
- **Firewall reported "active" for hosts with no firewall.** Docker (and fail2ban)
  create nftables/iptables chains; the check counted chains and rules. It now
  requires a default-deny inbound policy.
- **Containers reported "Running 0 services - minimal attack surface".** systemd
  was assumed whenever `systemctl` existed; zero services is now "cannot assess".
- **PATH Security failed on every merged-`/usr` system** (`stat` read the symlink's
  own mode, 777) and inspected the script's rewritten PATH instead of yours.
- **SUID, SGID and world-writable scans** covered only the root filesystem and
  flooded Docker hosts with container-layer files (measured: 125 against 11 real
  SUID files after pulling one image). They now scan every local mount and skip
  container storage. Stock-image SUID binaries are allowlisted by exact path and
  every message names the files.
- **Password login was missed** when `PasswordAuthentication no` coexisted with
  keyboard-interactive authentication and PAM.
- **Automatic updates** passed when `unattended-upgrades` was merely installed;
  dnf-automatic's default timer (which only downloads) passed; and an empty or
  stale apt index reported "all packages are up to date".
- **JSON was invalid** when a message contained a control character.
- **Empty-password accounts** were computed but never reported (and locked
  accounts were counted as empty).
- **Checks that read a command's output with `grep -q` or `head` could give the
  wrong answer when the command printed a lot.** The script runs under
  `set -o pipefail`; `producer | grep -q pattern` makes a producer that is
  still writing die of SIGPIPE, and `pipefail` then reports the match as a
  failure. Reproduced with 30,000 lines of output; the size at which real
  hosts hit it was not measured. Five checks were affected: iptables
  default-deny (a firewalled host with a large ruleset, typically Docker, could
  be reported as having no firewall), rarely used protocols that are loaded,
  `usb_storage` loaded, process-accounting data, and rootless Docker. A test
  now rejects the pattern.
- **Security updates were counted per advisory row on dnf/yum**, not per
  package: a fresh Rocky Linux 9 image printed "62 security updates (43
  total)". It now counts distinct packages.
- **`--no-network` still resolved the server's own name through DNS** (`hostname
  -f`, traced as a connect to the resolver) when the name was not in
  `/etc/hosts`. It no longer does; with `--no-network` the audit opens no
  connection to another machine (checked by tracing its socket calls).
- **Standard SGID helpers were reported as "outside the standard set"** on
  unmodified Ubuntu, RHEL-family, Amazon Linux and Arch images
  (`pam_extrausers_chkpwd`, `utempter`, `ssh-keysign`, `unix_chkpwd`).
- Messages use the singular where it applies ("1 security update available").
- Two recommendations said nothing useful: pending updates now name the
  package manager's upgrade command, and unreadable authentication logs
  explain what was looked for (it said "Run as root" to a script that already
  requires root).
- `--help` fits 80 columns, and `--no-network` is described as what it does.
- **Test harness:** `stub_bin` wrote through a link to a real utility and
  replaced `/usr/bin/hostname` when the suite ran as root. Two more problems
  appeared only on GitHub's runners and not on the maintainer's machine: the
  matrix could not read its own results when started by a non-root user (the
  audit's reports are root-owned, mode 600, and now belong to the invoking
  user afterwards), and two kernel-hardening tests depended on the network
  interfaces of the machine running them. All fixed. The `stub_bin` and
  interface fixes have tests; the matrix fix was checked by running one image
  as an unprivileged user before and after.
- **Failed-login counting** ignored `Invalid user` and pre-auth closes, the only
  lines written when password authentication is off.
- Open ports: DHCP client sockets and `address%interface` forms are handled, the
  owning process is shown, and databases bound to a specific public address are
  flagged (only wildcard binds were).
- IPv6 firewall detection understands native nftables policies.
- Time sync uses `NTPSynchronized`, recognises `ntpsec` and `openntpd`.
- Login banner detection no longer treats the stock `/etc/issue` of Alma, Rocky,
  Fedora, Alpine, Arch or Amazon Linux as a banner.
- `uptime` is no longer required (minimal Rocky, Alma and openSUSE images lack it).
- Sudoers: a mode of 600/640 is no longer flagged; `sudo-rs`'s `/etc/sudoers-rs`
  is scanned; advice to remove `NOPASSWD` warns about locking yourself out.
- Quick-start guide: keeps the current session open, validates with `sshd -t`,
  and says it is Debian/Ubuntu-oriented.

### Security
- Text from the audited system (usernames, paths, config lines) is no longer
  passed through `echo -e` or used as a format string, and control characters are
  stripped before printing, so it cannot inject escape sequences into the
  operator's terminal or the report.

### Removed
- Root-level `test-matrix.sh`, `tests/integration-tests.sh` (27 `grep` calls only
  searched the script's own source for strings, and ShellCheck 0.11 crashes on
  it) and `.github/workflows/docker-matrix.yml` (its per-distro job outputs all
  came from the same step output, so matrix legs overwrote each other, and its
  `((n++))` counters abort under `bash -e` when the counter is 0). Replaced by
  `tests/run.sh`, `tests/matrix.sh` and the new CI workflow.

## [2.4.0] - (previous maintainers' notes, kept as written)

Robustness, correctness, and security hardening pass.

**Correctness fixes**
- Fixed the `grep -c ... || echo 0` idiom (18+ sites) that produced a two-line
  `"0\n0"` on zero matches and broke numeric checks: a fully up-to-date system was
  misreported as "unable to determine updates". Update counting now also honours
  per-manager exit codes (dnf/yum `100`, pacman `1`).
- Open-ports check no longer drops UDP ports and correctly classifies `127.0.0.53`
  (systemd-resolved) and IPv6 addresses as loopback instead of "public".
- Core-dump check no longer reports a false PASS from the default
  `fs.suid_dumpable=0`; it requires an actual restriction.
- SUID/SGID scans use exact-path matching so a planted binary ending in a safe
  suffix (e.g. `/opt/evil/bin/su`) can no longer evade detection.
- Failed-login log matching handles single-digit days (`Jul  5`).
- Exposed-services check now detects IPv6-wildcard (`[::]:PORT`) database binds.
- Password-policy check reads `pwquality.conf.d/*` drop-ins and PAM inline args.

**Portability / robustness**
- Pinned `LC_ALL=C` for deterministic parsing; memory stats read `/proc/meminfo`
  directly; portable report-file creation; `df -P`; `portable_stat mtime`;
  `timeout`-guarded `hostname -f`.

**Security**
- Command-line flags now correctly override config-file values. Config files that
  are group- or world-writable are rejected.
- Hardened `PATH` and restrictive `umask` set for the whole run.
- SSH settings read from the effective configuration (`sshd -T`).

**Traceability and output**
- Timestamped report filenames; the report header records the invocation,
  package/service manager and coreutils variant; summary and JSON include run
  duration and score. JSON checks gained `recommendation` and `critical`.

## [2.3.0] - (previous maintainers' notes)
- Added advanced security checks: extended SSH hardening, sudoers `NOPASSWD`
  review, `/tmp` mount options, file-integrity monitoring (AIDE/Tripwire),
  rootkit scanners, legacy plaintext services, sensitive-file permissions, Docker
  daemon/container security, additional network sysctls, home-directory
  permissions, NFS export safety, root `PATH` safety, and exposed backend services.

## [2.2.0] - (previous maintainers' notes)
- Command availability detection with caching; portable `stat` wrapper; tool
  version detection; multi-distribution Docker test matrix; integration tests;
  GitHub Actions CI.

## [2.1.0] - (previous maintainers' notes)
- 14 production hardening checks (SSH key permissions, SGID files, cron security,
  network protocols, login banner, account lockout, umask, log permissions,
  Secure Boot / GRUB password, process accounting, IPv6, wireless, USB storage,
  compilers); `--guide`; priority-ordered recommendations; security scores; Bash
  version check; configuration-file ownership/permission validation.

## [2.0.0] - (original project)
- Complete refactoring with multi-distro support; JSON output; command-line
  options and configuration files; MAC, kernel hardening and user auditing checks;
  proper exit codes; summary statistics and recommendations; secure report files.
