#!/usr/bin/env bash
#
# Distro and Bash-version matrix. Runs, inside a disposable container per
# image: the unit suites, real-state scenarios (nftables, mounts, accounts,
# sshd), and one full audit. The host then validates what came back: the JSON
# report must parse and be internally consistent, the exit code must agree
# with the summary, and neither stream may contain a Bash runtime error.
#
#   tests/matrix.sh                  every image
#   tests/matrix.sh ubuntu alpine    images whose name contains a filter
#   tests/matrix.sh -j 4             four images at a time
#   tests/matrix.sh -l               list images
#
# Needs a Docker daemon. Containers run with --privileged (they are disposable
# and the scenarios mount filesystems and load nftables rules). Images already
# present locally are not pulled again. Environment:
#   DOCKER_RUN_ARGS   extra `docker run` flags
#   EXTRA_CA_BUNDLE   PEM file to trust inside the containers (for networks
#                     that intercept TLS with their own CA)
# Results are kept in test-results/<image>/ (gitignored).

set -o pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${RESULTS_DIR:-$REPO_DIR/test-results}"

# image|label|kind. kind "distro" runs everything. "bash" images (official Bash
# builds on Alpine) run everything too, to cover Bash versions. "floor" images
# (Bash 4.0-4.3, older than the test harness supports) run only the full audit,
# which is what proves the minimum Bash version the script claims.
# Supported releases per https://endoflife.date as of 2026-10; the official
# Docker Hub `rockylinux` repository is stale (9.3), so the vendor repo is used.
MATRIX=(
    "ubuntu:26.04|Ubuntu 26.04 LTS|distro"
    "ubuntu:24.04|Ubuntu 24.04 LTS|distro"
    "ubuntu:22.04|Ubuntu 22.04 LTS|distro"
    "debian:13|Debian 13 (trixie)|distro"
    "debian:12|Debian 12 (bookworm)|distro"
    "fedora:44|Fedora 44|distro"
    "fedora:43|Fedora 43|distro"
    "rockylinux/rockylinux:10|Rocky Linux 10|distro"
    "rockylinux/rockylinux:9|Rocky Linux 9|distro"
    "almalinux:10|AlmaLinux 10|distro"
    "almalinux:9|AlmaLinux 9|distro"
    "amazonlinux:2023|Amazon Linux 2023|distro"
    "opensuse/leap:16.0|openSUSE Leap 16.0|distro"
    "archlinux:latest|Arch Linux|distro"
    "alpine:3.24|Alpine 3.24|distro"
    "alpine:3.23|Alpine 3.23|distro"
    "alpine:3.22|Alpine 3.22|distro"
    "bash:4.0|GNU Bash 4.0|floor"
    "bash:4.1|GNU Bash 4.1|floor"
    "bash:4.2|GNU Bash 4.2|floor"
    "bash:4.3|GNU Bash 4.3|floor"
    "bash:4.4|GNU Bash 4.4|bash"
    "bash:5.1|GNU Bash 5.1|bash"
    "bash:5.3|GNU Bash 5.3|bash"
)

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_GREEN=$'\033[32m' C_RED=$'\033[31m' C_OFF=$'\033[0m'
else
    C_GREEN='' C_RED='' C_OFF=''
fi

usage() {
    sed -n '3,22p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

safe_name() {
    local s="${1//[:\/]/_}"
    printf '%s' "$s"
}

# --- validation of one container's results -------------------------------------
# Prints one problem per line; no output means the leg is valid.
validate_result() {
    local dir="$1" kind="$2" f
    local -a need=(env.txt tests.exit scenarios.exit audit.exit audit.stdout audit.stderr)
    for f in "${need[@]}"; do
        [[ -e "$dir/$f" ]] || {
            echo "missing result file: $f (the container run did not finish)"
            return 0
        }
    done

    # Floor images skip the unit tests (the harness needs Bash 4.4) and say so with 77.
    case "$(cat "$dir/tests.exit")" in
        0) ;;
        77) [[ "$kind" == "floor" ]] || echo "unit tests were skipped (see tests.log)" ;;
        *) echo "unit tests failed (see tests.log)" ;;
    esac
    # 77 means "skipped: prerequisite missing" - allowed only for scenarios.
    case "$(cat "$dir/scenarios.exit")" in
        0 | 77) ;;
        *) echo "scenarios failed (see scenarios.log)" ;;
    esac

    local rc
    rc="$(cat "$dir/audit.exit")"
    case "$rc" in
        0 | 1 | 2) ;;
        *) echo "full audit exited $rc (expected 0, 1 or 2)" ;;
    esac

    # Bash runtime errors leak to stderr when a check mis-parses something.
    local pat='line [0-9]+: |command not found|syntax error|bad substitution|unbound variable|integer expression expected|unary operator expected|binary operator expected|ambiguous redirect|division by 0|value too great for base|invalid arithmetic operator|readonly variable|cannot overwrite existing file|not a valid identifier'
    if grep -Eq "$pat" "$dir/audit.stderr" "$dir/audit.stdout" 2>/dev/null; then
        echo "Bash runtime error in audit output:"
        grep -Eh "$pat" "$dir/audit.stderr" "$dir/audit.stdout" | head -3 | sed 's/^/    /'
    fi

    local json report
    json="$(compgen -G "$dir/vps-audit-report-*.json" | head -n 1)"
    report="${json%.json}.txt"
    if [[ -z "$json" ]]; then
        echo "no JSON report was written"
        return 0
    fi
    jq -e . "$json" >/dev/null 2>&1 || {
        echo "JSON report is not valid JSON"
        return 0
    }

    local cats
    cats="$("$REPO_DIR/vps-audit.sh" --help | awk '/^Check Categories/ {on=1; next} /^$/ {on=0} on {print $1}' | tr '\n' ' ')"
    jq -e --arg cats "$cats" '
        ($cats | split(" ") | map(select(length > 0))) as $valid
        | .summary as $s
        | ([.checks[] | select(.status != "INFO")] | length) as $scored
        | ([.checks[] | select(.status == "INFO")] | length) as $info
        | ($s.total == $scored)
        and ($s.info == $info)
        and ($s.pass + $s.warn + $s.fail == $s.total)
        and ((.checks | length) >= 45)
        and ($s.critical_fail == ([.checks[] | select(.critical)] | length))
        and (.schema_version == 1)
        and all(.checks[];
            (.name | length > 0)
            and (.status | IN("PASS", "WARN", "FAIL", "INFO"))
            and (.category as $c | $valid | index($c) != null)
            and (.critical | type == "boolean")
            and ((.status == "PASS") == (.priority == null))
            and (.message | test("\n") | not))
    ' "$json" >/dev/null 2>&1 || echo "JSON report failed structural validation (counts, categories, fields)"

    local crit fails
    crit="$(jq '.summary.critical_fail' "$json" 2>/dev/null)"
    fails="$(jq '.summary.fail' "$json" 2>/dev/null)"
    if [[ "$crit" =~ ^[0-9]+$ && "$fails" =~ ^[0-9]+$ ]]; then
        local want=0
        [[ $fails -gt 0 ]] && want=1
        [[ $crit -gt 0 ]] && want=2
        [[ "$rc" == "$want" ]] || echo "exit code $rc disagrees with summary (fail=$fails critical=$crit => $want)"
    fi

    # Verified claims about behaviour that must hold on every distro:
    # a plain container has no systemd and no firewall rules.
    jq -e '[.checks[] | select(.name == "Running Services") | .message | test("Running 0 services")] | any | not' \
        "$json" >/dev/null 2>&1 || echo "Running Services reported '0 services' as healthy without a service manager"
    if [[ "$kind" == "distro" ]]; then
        jq -e '[.checks[] | select(.name | startswith("Firewall Status")) | .status == "FAIL"] | all' \
            "$json" >/dev/null 2>&1 || echo "Firewall Status must FAIL in a container with no rules"
        # Every image in the matrix is meant to be a supported release. A FAIL
        # here means the release has reached end of support: refresh the matrix.
        jq -e '[.checks[] | select(.name == "OS Support") | .status != "FAIL"] | all' \
            "$json" >/dev/null 2>&1 || echo "OS Support reports this image as past end of support: update the matrix image list"
    fi

    local mode
    for f in "$json" "$report"; do
        [[ -f "$f" ]] || continue
        mode="$(stat -c %a "$f" 2>/dev/null)"
        [[ "$mode" == 600 ]] || echo "$(basename "$f") has mode $mode (expected 600)"
    done
}

# --- one image ------------------------------------------------------------------
run_one() {
    local image="$1" label="$2" kind="$3"
    local dir
    dir="$RESULTS_DIR/$(safe_name "$image")"
    rm -rf "$dir"
    mkdir -p "$dir"

    # Docker Hub rate-limits anonymous pulls (429); retry a few times. An image
    # that is already local is used as is.
    local tries=0
    until docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >"$dir/pull.log" 2>&1; do
        tries=$((tries + 1))
        if [[ $tries -ge 4 ]]; then
            echo "FAIL|$image|$label|could not pull image (see pull.log)"
            return 0
        fi
        sleep $((tries * 8))
    done

    local -a ca_args=()
    [[ -n "${EXTRA_CA_BUNDLE:-}" ]] && ca_args=(-v "$EXTRA_CA_BUNDLE:/extra-ca.crt:ro")

    # shellcheck disable=SC2086  # DOCKER_RUN_ARGS is deliberately word-split
    docker run --rm --privileged -e "MATRIX_KIND=$kind" ${DOCKER_RUN_ARGS:-} "${ca_args[@]}" \
        -v "$REPO_DIR:/src:ro" -v "$dir:/out" --entrypoint sh "$image" -c '
            sh /src/tests/container/setup.sh >/out/setup.log 2>&1
            echo $? >/out/setup.exit
            command -v bash >/dev/null 2>&1 || { echo "no bash in image" >/out/no-bash; exit 1; }
            exec bash /src/tests/container/run.sh
        ' >"$dir/container.log" 2>&1

    local -a problems=()
    mapfile -t problems < <(validate_result "$dir" "$kind")
    [[ "$(cat "$dir/setup.exit" 2>/dev/null)" == 0 ]] || problems+=("package setup failed (see setup.log); results reflect a reduced tool set")

    local bashv tests_line
    bashv="$(awk '/^bash:/ {print $2}' "$dir/env.txt" 2>/dev/null)"
    tests_line="$(grep -E '^Ran [0-9]+ tests' "$dir/tests.log" 2>/dev/null | tail -n 1)"
    [[ -z "$tests_line" && "$kind" == "floor" ]] && tests_line="audit only"
    local summary="bash ${bashv:-?}; ${tests_line:-no test summary}"
    # One write per image keeps parallel jobs from interleaving their output.
    local result
    if [[ ${#problems[@]} -eq 0 ]]; then
        result="PASS|$image|$label|$summary"
    else
        result="FAIL|$image|$label|$summary"
        local p
        for p in "${problems[@]}"; do
            result+=$'\n'"    - $p"
        done
    fi
    printf '%s\n' "$result"
}

main() {
    local jobs=1 list=false
    local -a filters=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h | --help)
                usage
                exit 0
                ;;
            -l | --list) list=true ;;
            -j)
                jobs="${2:?-j needs a number}"
                shift
                ;;
            --run-one)
                shift
                run_one "$@"
                exit 0
                ;;
            *) filters+=("$1") ;;
        esac
        shift
    done

    local -a selected=()
    local entry f
    for entry in "${MATRIX[@]}"; do
        if [[ ${#filters[@]} -eq 0 ]]; then
            selected+=("$entry")
            continue
        fi
        for f in "${filters[@]}"; do
            [[ "$entry" == *"$f"* ]] && {
                selected+=("$entry")
                break
            }
        done
    done
    if [[ ${#selected[@]} -eq 0 ]]; then
        echo "no image matches: ${filters[*]}" >&2
        exit 2
    fi

    if $list; then
        for entry in "${selected[@]}"; do
            IFS='|' read -r image label kind <<<"$entry"
            printf '%-28s %-24s %s\n' "$image" "$label" "$kind"
        done
        exit 0
    fi

    command -v docker >/dev/null 2>&1 || {
        echo "docker is not installed" >&2
        exit 2
    }
    docker info >/dev/null 2>&1 || {
        echo "cannot reach the Docker daemon" >&2
        exit 2
    }
    command -v jq >/dev/null 2>&1 || {
        echo "jq is required on the host" >&2
        exit 2
    }
    mkdir -p "$RESULTS_DIR"

    echo "Running ${#selected[@]} image(s), $jobs at a time. Results: $RESULTS_DIR"
    local out
    # The single-quoted script is expanded by the inner bash, not here.
    # shellcheck disable=SC2016
    out="$(for entry in "${selected[@]}"; do printf '%s\0' "$entry"; done |
        xargs -0 -n1 -P "$jobs" bash -c 'IFS="|" read -r i l k <<<"$1"; "$0" --run-one "$i" "$l" "$k"' "${BASH_SOURCE[0]}" 2>&1)"

    local pass=0 fail=0 line
    while IFS= read -r line; do
        case "$line" in
            PASS\|*)
                pass=$((pass + 1))
                IFS='|' read -r _ image label summary <<<"$line"
                printf '%sPASS%s  %-28s %s\n' "$C_GREEN" "$C_OFF" "$image" "$summary"
                ;;
            FAIL\|*)
                fail=$((fail + 1))
                IFS='|' read -r _ image label summary <<<"$line"
                printf '%sFAIL%s  %-28s %s\n' "$C_RED" "$C_OFF" "$image" "$summary"
                ;;
            *) printf '%s\n' "$line" ;;
        esac
    done <<<"$out"

    echo
    printf '%d passed, %d failed of %d\n' "$pass" "$fail" "${#selected[@]}"
    [[ $fail -eq 0 && $pass -gt 0 ]]
}

main "$@"
