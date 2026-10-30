# shellcheck shell=bash
# Test helpers: load the script's functions without running it, and run fixes
# the way --fix does.

REPO="$(cd "$BATS_TEST_DIRNAME/.." && pwd)"
SCRIPT="${SCRIPT:-$REPO/emudhra-check.sh}"

# load_script : source the script without its run block (everything from the
# line EMD_ORIG_ARGS=("$@") on), then set up state like main() does, quietly
load_script() {
  sed '/^EMD_ORIG_ARGS=/,$d' "$SCRIPT" > "$BATS_TEST_TMPDIR/lib.sh"
  # shellcheck disable=SC1091
  source "$BATS_TEST_TMPDIR/lib.sh"
  parse_options
  init_state
  detect_environment
  # used by the sourced script's functions
  # shellcheck disable=SC2034
  LOG=/dev/null PRETTY=0 OPT_COLOR=0 TERM_W=100 EMD_TMP=$BATS_TEST_TMPDIR
}

# run_fix FUNCTION ARGS... : register a fix and run it through fx_run, the
# path --fix uses (a fresh bash that only gets the fix_* functions)
run_fix() {
  add_fix 0 "test" "$@"
  fx_run $((FX_N - 1)) "$BATS_TEST_TMPDIR/fix.out"
  local rc=$?
  cat "$BATS_TEST_TMPDIR/fix.out"
  return "$rc"
}
