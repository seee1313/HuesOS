#!/usr/bin/env bash
# TEMPORARY (this branch only): run one HuesOS gate and publish its failure
# details as GitHub check annotations, because job logs cannot be downloaded
# from this environment (the log blob storage returns EOF) while the check-run
# annotations API does work.
#
# Usage: bash scripts/arena-diag.sh <fmt|fmt-diff|clippy|test|audit>
#
# Every command runs with `continue-on-error` from the workflow's point of
# view, so one invocation reports on exactly one gate and always exits 0 after
# publishing the evidence.
set -uo pipefail

gate="${1:-fmt}"
log="/tmp/arena-diag-${gate}.log"
: >"$log"

annotate() {
    local file="$1"
    local lines="${2:-40}"
    # GitHub caps a step at 10 annotations of each level and 50 total; keep to
    # a bounded tail and escape the workflow-command metacharacters.
    tail -n "$lines" "$file" 2>/dev/null | cut -c1-220 | sed 's/%/%25/g; s/\r//g' |
        while IFS= read -r line; do
            printf '::error file=arena-diag/%s::%s\n' "$gate" "$line"
        done
}

echo "=== gate: $gate"
case "$gate" in
    fmt)
        python3 tools/fmt-all.py --check >>"$log" 2>&1
        status=$?
        if [ "$status" -ne 0 ]; then
            echo "fmt --check failed; capturing the diff the formatter wants"
            python3 tools/fmt-all.py >>/tmp/arena-diag-fmt-fixed.log 2>&1
            git --no-pager diff >/tmp/arena-diag-fmt.diff
            annotate /tmp/arena-diag-fmt.diff 60
            echo "--- summary"
            tail -n 20 "$log"
        fi
        ;;
    clippy)
        make clippy >>"$log" 2>&1
        status=$?
        [ "$status" -ne 0 ] && annotate "$log" 60
        ;;
    test)
        make test >>"$log" 2>&1
        status=$?
        [ "$status" -ne 0 ] && annotate "$log" 60
        ;;
    audit)
        make audit-check >>"$log" 2>&1
        status=$?
        [ "$status" -ne 0 ] && annotate "$log" 40
        ;;
    *)
        echo "unknown gate: $gate" >&2
        exit 2
        ;;
esac

echo "gate ${gate} exited ${status:-0}"
# The diagnostics job is informational: never fail it, or the annotations are
# buried under a red X with no detail.
exit 0
