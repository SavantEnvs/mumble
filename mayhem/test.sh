#!/usr/bin/env bash
#
# mayhem/test.sh — RUN mumble's own QtTest suites plus a known-answer probe (all built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TESTS="$SRC/build/mayhem/tests"
export QT_QPA_PLATFORM=offscreen

if [ ! -d "$TESTS" ]; then
  echo "FAIL: $TESTS missing — mayhem/build.sh did not build the test suite" >&2
  emit_ctrf "mumble-qttest" 0 1 0
  exit 1
fi

passed=0 failed=0 skipped=0 binaries=0
for t in "$TESTS"/Test*; do
  [ -x "$t" ] || continue
  out="$("$t" 2>&1)"
  totals="$(printf '%s\n' "$out" | sed -n 's/^Totals: \([0-9]*\) passed, \([0-9]*\) failed, \([0-9]*\) skipped.*/\1 \2 \3/p' | tail -1)"
  if [ -z "$totals" ]; then
    echo "FAIL: $(basename "$t") printed no 'Totals:' line" >&2
    failed=$((failed + 1))
    continue
  fi
  read -r p f s <<<"$totals"
  binaries=$((binaries + 1))
  passed=$((passed + p)); failed=$((failed + f)); skipped=$((skipped + s))
  printf '%s: %s passed, %s failed, %s skipped\n' "$(basename "$t")" "$p" "$f" "$s"
done

# QtTest binaries that were built must all have reported; a sabotaged/no-op binary prints nothing.
if [ "$binaries" -lt 15 ]; then
  echo "FAIL: expected 15 QtTest binaries to report, got $binaries" >&2
  failed=$((failed + 1))
fi

# Known-answer probe: wire-format values computed by the real code must match the golden output.
probe_out="$("$TESTS/kat_probe" 2>/dev/null)"
read -r -d '' GOLDEN <<'EOF_GOLDEN'
varint=9234fdf40000010000000000
varint_decoded=4660,-2,1099511627776
version=281496493096960 legacy=67071 str=1.5.634
ping=010885888c9010
ping_decoded=1,4328719365
ocb_crypt=f262afbd2da2fe0fbee8ba910d621ae6
ocb_tag=40227aa69c418ed365e9176c3c5e55f3
host=1.1.168.192
EOF_GOLDEN
while IFS= read -r line; do
  [ -n "$line" ] || continue
  if printf '%s\n' "$probe_out" | grep -qxF -- "$line"; then
    passed=$((passed + 1))
  else
    echo "FAIL: kat_probe missing expected line: $line" >&2
    failed=$((failed + 1))
  fi
done <<<"$GOLDEN"

emit_ctrf "mumble-qttest" "$passed" "$failed" "$skipped"
