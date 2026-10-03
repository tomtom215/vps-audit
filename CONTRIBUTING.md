# Contributing to VPS Audit

Thanks for helping. The goal is a read-only audit that a person who has just
provisioned a VPS can run and trust: every verdict should be correct, every
recommendation should say what to do, and nothing should surprise the operator.

## Setup

You need Bash, `git`, and `jq`. For the full workflow you also want Docker.

```bash
# Linters pinned exactly as CI pins them (needs Python 3):
python3 -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r .github/requirements-lint.txt
# actionlint (only needed if you touch workflows): https://github.com/rhysd/actionlint
```

## The loop

```bash
./tests/run.sh                    # unit + CLI tests, a few seconds, no Docker
./tests/run.sh -k firewall        # only tests whose name contains "firewall"
sudo ./tests/run.sh               # as root: also runs the tests that need root
shellcheck -x $(git ls-files '*.sh')
shfmt -w $(git ls-files '*.sh')   # formatting is enforced; options come from .editorconfig
tests/matrix.sh ubuntu:24.04      # one distro in a container (needs Docker)
tests/matrix.sh -j 4              # every distro and Bash version
```

CI runs all of the above on every push. `tests/matrix.sh -l` lists the images; it
is the single list CI reads.

## Repository layout

| Path | What it is |
|------|------------|
| `vps-audit.sh` | The tool. One file on purpose: people download and run it. |
| `tests/run.sh`, `tests/lib.sh` | Test runner and helpers (assertions, stubbing). |
| `tests/test_*.sh` | Test suites. Every `test_*` function runs in its own subshell. |
| `tests/fixtures/` | Real command output captured from real systems. |
| `tests/matrix.sh`, `tests/container/` | Distro/Bash matrix: unit tests, real-state scenarios and a full audit inside a container per image. |
| `.github/workflows/` | CI and release. |

## Principles

- **Read-only.** A check inspects; it never changes configuration.
- **A verdict is a claim.** PASS means the thing was checked and is fine. If a
  tool is missing or output cannot be parsed, say so with a WARN - never PASS by
  default, and never report an unreadable value as zero.
- **Degrade gracefully.** Any optional tool may be absent. Prefer `/proc` and
  plain files over extra commands (the script reads uptime and load from
  `/proc` because minimal images have no `uptime`).
- **System text is hostile.** Usernames, paths and config lines can contain
  anything. Print them with `%s` only, never through `echo -e` or as a format
  string, and never `eval` them.
- **ASCII output only**, wrapped to the terminal when stdout is a terminal.
- No `set -e` / `set -u`: checks probe things that may legitimately be absent,
  and errors are handled at each call site.

## Adding a check

1. Pick or add a category in `CHECK_CATEGORIES` (top of `vps-audit.sh`). This one
   array drives `--checks` validation, `--help`, `--dry-run` and the README table.
2. Write `check_<name>()`. Start with `should_run_check "<category>" || return 0`,
   report with `check_security NAME STATUS MESSAGE [RECOMMENDATION] [critical]`,
   and add the call to `main()`.
   - STATUS is `PASS`, `WARN` or `FAIL`. Only a `FAIL` can be `critical`.
   - Recommendation priority follows the verdict (`compute_priority`); a WARN
     from a purely defence-in-depth check belongs in its "low" list.
   - The recommendation must state the wanted value, not the current one.
3. Test it (below). A bug fix needs a regression test that **fails without the fix**.
4. Update the README category table if you added a category, and `CHANGELOG.md`.

## Writing tests

Drive the check with stubbed commands and fixture files, and assert on the
verdict:

```bash
test_my_check_flags_the_bad_state() {
    hide_system_commands                 # only basic utilities are on PATH
    stub ufw 'echo "Status: inactive"'   # shell-function stub for a command
    record_checks                        # check_security now records instead of printing
    check_firewall_status
    assert_eq FAIL "$RESULT_STATUS" "$RESULT_MSG" || return 1
}
```

- `stub_bin` writes a real executable instead (needed when the code runs the
  command through `timeout`, `xargs`, etc.).
- System files are variables (`PASSWD_FILE`, `SHADOW_FILE`, `PROC_MOUNTS`, ...)
  that a test can point at a fixture after the script is sourced.
- Fixtures should be **real output** captured from the real tool (see
  `tests/fixtures/firewall/`), not hand-written guesses.
- If the behaviour depends on real kernel or package state (nftables rules, a
  mounted filesystem, `sshd -T`), add a scenario to
  `tests/container/scenarios.sh` instead.
- Tests must work on Bash 4.4 and later: no `declare -g`, `local -n`, or
  `[[ -v ]]`.
- Each file under `tests/` starts with `# shellcheck shell=bash disable=...`
  naming only the codes it needs. They are structural to the harness, not
  excuses: `SC2034`/`SC2154` (variables the sourced `vps-audit.sh` reads or sets,
  which ShellCheck cannot see), `SC2016` (a stub body is code held in single
  quotes) and `SC2329` (`test_*` functions and stubs are called by name). The
  scripts that are not tests (`vps-audit.sh`, `tests/matrix.sh`,
  `tests/container/`, `tools/`) have no file-level exemptions, only a few
  single-line ones that each say why.

## Commits and pull requests

Conventional prefixes: `feat`, `fix`, `docs`, `test`, `ci`, `refactor`. Say what
changed and why in the body. Before opening a pull request run `./tests/run.sh`,
`shellcheck -x`, `shfmt -d`, and (if you changed behaviour that depends on a
distribution) the matrix for the affected images.

## Releasing (maintainers)

1. Bump `readonly VERSION` in `vps-audit.sh`.
2. Add a `## [X.Y.Z] - date` section to `CHANGELOG.md`.
3. Merge, then push a tag `vX.Y.Z`. The release workflow checks that the tag, the
   version and the changelog agree, runs the tests, publishes the script with
   `SHA256SUMS`, and attaches a build-provenance attestation.

## Updating pinned CI tools

Actions are pinned by commit SHA and the linters by hash; Dependabot proposes
updates for both. The actionlint version and checksum in `ci.yml` are the one pin
Dependabot cannot see: update `ACTIONLINT_VERSION` and `ACTIONLINT_SHA256`
together (the checksum is in the release's `actionlint_X.Y.Z_checksums.txt`).

## Reporting issues

Please use the issue forms. For a check that gave the wrong verdict, include the
command output that shows the server's real state. Report security problems
privately - see [SECURITY.md](SECURITY.md).
