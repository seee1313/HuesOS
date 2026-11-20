#!/usr/bin/env bash
# TEMPORARY (this branch only): run one HuesOS gate and publish its failure
# details as GitHub check annotations, because job logs cannot be downloaded
# from this environment (the log blob storage returns EOF) while the check-run
# annotations API does work.
#
# Usage: bash scripts/arena-diag.sh <fmt|clippy|test|audit>
#
# Each invocation reports on exactly one gate and always exits 0: the workflow
# job is a messenger, not a gate.
set -uo pipefail

gate="${1:-fmt}"
log="/tmp/arena-diag-${gate}.log"
: >"$log"

# Emit one annotation carrying many lines: the annotations API keeps only a
# handful per step, so a single large message is the only way to get a whole
# compiler error out through this channel.
emit() {
    local title="$1"
    local body_file="$2"
    local max_chars="${3:-6000}"
    local message
    message=$(tr -d '\r' <"$body_file" | head -c "$max_chars" | sed 's/%/%25/g' | sed ':a;N;$!ba;s/\n/%0A/g')
    printf '::error file=arena-diag/%s,line=1,title=%s::%s\n' "$gate" "$title" "$message"
}

# The interesting lines of a build/test log: errors, failures, assertion
# output, and the last few lines (which usually name the failing target).
interesting() {
    local file="$1"
    {
        grep -nE "^(error|warning: unused|failures:|test result: FAILED)|error\[E[0-9]+\]|panicked at|assertion .* failed|^---- |^left:|^right:|FAILED" "$file" || true
        echo "----- last 12 lines -----"
        tail -n 12 "$file"
    } >"$file.interesting"
}

echo "=== gate: $gate"
status=0
case "$gate" in
    fmt)
        python3 tools/fmt-all.py --check >>"$log" 2>&1
        status=$?
        if [ "$status" -ne 0 ]; then
            python3 tools/fmt-all.py >>/tmp/arena-diag-fmt-fixed.log 2>&1
            git --no-pager diff >/tmp/arena-diag-fmt.diff
            # Only the changed hunks matter; the ---/+++ headers are noise.
            grep -E "^(\+|-|@@)" /tmp/arena-diag-fmt.diff >/tmp/arena-diag-fmt.hunks || true
            emit "fmt-diff" /tmp/arena-diag-fmt.hunks 6000
            emit "fmt-summary" "$log" 1500
        fi
        ;;
    clippy | test)
        make "$gate" >>"$log" 2>&1
        status=$?
        if [ "$status" -ne 0 ]; then
            interesting "$log"
            emit "${gate}-errors" "$log.interesting" 6000
        fi
        ;;
    audit)
        make audit-check >>"$log" 2>&1
        status=$?
        [ "$status" -ne 0 ] && emit "audit-errors" "$log" 3000
        ;;
    *)
        echo "unknown gate: $gate" >&2
        exit 2
        ;;
esac

echo "gate ${gate} exited ${status}"
exit 0
