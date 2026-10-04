#!/usr/bin/env bash
#
# Test runner for vps-audit.
#
#   tests/run.sh                 run every suite
#   tests/run.sh cli checks      run only suites tests/test_cli.sh, test_checks.sh
#   tests/run.sh -k firewall     run only tests whose name contains "firewall"
#   tests/run.sh -l              list tests without running them
#
# Each test_* function runs in its own subshell. Exit status is 0 only if every
# selected test passed. See tests/lib.sh for the assertion helpers.

set -o pipefail

# shellcheck source=tests/lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
    C_GREEN=$'\033[32m' C_RED=$'\033[31m' C_DIM=$'\033[2m' C_OFF=$'\033[0m'
else
    C_GREEN='' C_RED='' C_DIM='' C_OFF=''
fi

filter=""
list_only=false
suites=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -k)
            filter="${2:?-k needs a substring}"
            shift
            ;;
        -l) list_only=true ;;
        -h | --help)
            sed -n '3,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) suites+=("$1") ;;
    esac
    shift
done

if [[ ${#suites[@]} -eq 0 ]]; then
    for f in "$TESTS_DIR"/test_*.sh; do
        suites+=("$(basename "$f" .sh | sed 's/^test_//')")
    done
fi

TEST_TMPLIST="$(mktemp)"
export TEST_TMPLIST
trap 'rm -f "$TEST_TMPLIST"' EXIT

total=0 passed=0 failed=0 skipped=0
failed_names=()
start=$SECONDS

for suite in "${suites[@]}"; do
    file="$TESTS_DIR/test_${suite}.sh"
    if [[ ! -f "$file" ]]; then
        echo "unknown suite: $suite" >&2
        exit 2
    fi
    # Collect test names defined by this suite (functions beginning with test_).
    before="$(declare -F | awk '{print $3}' | grep '^test_' | sort || true)"
    # shellcheck source=/dev/null
    source "$file"
    after="$(declare -F | awk '{print $3}' | grep '^test_' | sort || true)"
    mapfile -t names < <(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after"))

    for name in "${names[@]}"; do
        [[ -n "$filter" && "$name" != *"$filter"* ]] && continue
        if $list_only; then
            echo "$suite: $name"
            continue
        fi
        total=$((total + 1))
        t0=$SECONDS
        # Source the script under test at the subshell's top level so its
        # declare -A / readonly state are globals (see tests/lib.sh).
        output="$( (
            # shellcheck source=/dev/null
            source "$AUDIT_SCRIPT" || exit 99
            set +o noclobber
            "$name"
        ) 2>&1)"
        rc=$?
        # Remove every scratch directory the test created, however it ended.
        while IFS= read -r scratch; do
            [[ -n "$scratch" ]] && chmod -R u+rwx "$scratch" 2>/dev/null
            [[ -n "$scratch" ]] && rm -rf "$scratch"
        done <"$TEST_TMPLIST"
        : >|"$TEST_TMPLIST"
        if [[ $rc -eq 77 ]]; then
            skipped=$((skipped + 1))
            printf '%sskip%s  %s\n' "$C_DIM" "$C_OFF" "$suite/${name#test_}"
        elif [[ $rc -eq 0 ]]; then
            passed=$((passed + 1))
            printf '%sok%s    %s %s(%ss)%s\n' "$C_GREEN" "$C_OFF" "$suite/${name#test_}" "$C_DIM" "$((SECONDS - t0))" "$C_OFF"
        else
            failed=$((failed + 1))
            failed_names+=("$suite/${name#test_}")
            printf '%sFAIL%s  %s (exit %s)\n' "$C_RED" "$C_OFF" "$suite/${name#test_}" "$rc"
            [[ -n "$output" ]] && printf '%s\n' "$output" | sed 's/^/        /'
        fi
    done
done

$list_only && exit 0

echo
printf 'Ran %d tests in %ds: %s%d passed%s, %s%d failed%s, %d skipped\n' \
    "$total" "$((SECONDS - start))" "$C_GREEN" "$passed" "$C_OFF" "$C_RED" "$failed" "$C_OFF" "$skipped"
if [[ $failed -gt 0 ]]; then
    printf 'Failed:\n'
    printf '  %s\n' "${failed_names[@]}"
    exit 1
fi
[[ $total -gt 0 ]] || {
    echo "no tests selected" >&2
    exit 2
}
exit 0
