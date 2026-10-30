#!/usr/bin/env bats
# Go: the version check compares within a release line (1.26.x with 1.26.10,
# 1.27.x with 1.27.3), and --fix can reinstall a go.dev Go (/usr/local/go)
# from the official installer, after checking its SHA-256 and Google's signature.
# No test downloads or installs anything: fakes stand in for go, the download
# location and the installer.

load helpers/load

setup() {
  cd "$REPO" || return 1
  load_script
  ARCH=$(uname -m); [ "$ARCH" = x86_64 ] && ARCH=amd64
  mkdir -p "$BATS_TEST_TMPDIR/bin"
  PATH="$BATS_TEST_TMPDIR/bin:$PATH"
}

# fake_go DIR VERSION : a go binary in DIR that reports VERSION
fake_go() {
  mkdir -p "$1"
  printf '#!/bin/sh\necho "go version go%s darwin/%s"\n' "$2" "$ARCH" > "$1/go"
  chmod +x "$1/go"
}

# fake_download VERSION SHA256 : a fake installer and its .sha256 file in a
# local folder used as the download location; the fake installer program
# records whether it ran
fake_download() {
  local dl="$BATS_TEST_TMPDIR/dl" pkg="go$1.darwin-$ARCH.pkg"
  mkdir -p "$dl"
  echo "not a real package" > "$dl/$pkg"
  echo "$2  $pkg" > "$dl/$pkg.sha256"
  export GO_DL_BASE="file://$dl"
  printf '#!/bin/sh\ntouch "%s/installer-ran"\n' "$BATS_TEST_TMPDIR" > "$BATS_TEST_TMPDIR/bin/installer"
  chmod +x "$BATS_TEST_TMPDIR/bin/installer"
}

@test "go_release_for picks the patched release of the same line" {
  [ "$(go_release_for 1.26.4 "$FIX_GO")" = 1.26.10 ]
  [ "$(go_release_for 1.27.1 "$FIX_GO")" = 1.27.3 ]
  [ -z "$(go_release_for 1.27.3 "$FIX_GO")" ]
  [ -z "$(go_release_for 1.28.0 "$FIX_GO")" ]
  [ "$(go_release_for 1.25.9 "$FIX_GO")" = 1.27.3 ]
}

@test "check_go: Go 1.27.1 is not a patched release" {
  fake_go "$BATS_TEST_TMPDIR/bin" 1.27.1
  run check_go
  [[ "$output" == *"[WARN] go 1.27.1"* ]] || false
  [[ "$output" == *"need 1.27.3"* ]]
}

@test "check_go: a go.dev install gets the go.dev installer fix" {
  GO_PKG_ROOT="$BATS_TEST_TMPDIR/usr/local/go"
  fake_go "$GO_PKG_ROOT/bin" 1.26.4
  PATH="$GO_PKG_ROOT/bin:$PATH"
  check_go > /dev/null
  [ "$FX_N" -eq 1 ]
  [[ "${FX_LABEL[0]}" == *"Install Go 1.26.10 from go.dev"* ]] || false
  [ "${FX_SUDO[0]}" = 1 ]
  fx_words 0
  [ "${FX_WORDS[0]}" = fix_go_pkg ]
  [ "${FX_WORDS[1]}" = 1.26.10 ]
}

@test "check_go: a Go installed some other way keeps the manual instructions" {
  fake_go "$BATS_TEST_TMPDIR/bin" 1.26.4
  run check_go
  [[ "$output" == *"Install a patched Go from https://go.dev/dl/"* ]]
  check_go > /dev/null
  [ "$FX_N" -eq 0 ]
}

@test "fix_go_pkg refuses a download whose SHA-256 does not match" {
  fake_download 1.27.3 0000000000000000000000000000000000000000000000000000000000000000
  run run_fix fix_go_pkg 1.27.3
  [ "$status" -ne 0 ]
  [[ "$output" == *"SHA-256 mismatch"* ]] || false
  [ ! -e "$BATS_TEST_TMPDIR/installer-ran" ]
}

@test "fix_go_pkg refuses a package that is not signed by Google" {
  local sum
  fake_download 1.27.3 placeholder
  sum=$(shasum -a 256 "$BATS_TEST_TMPDIR/dl/go1.27.3.darwin-$ARCH.pkg" | awk '{print $1}')
  echo "$sum  go1.27.3.darwin-$ARCH.pkg" > "$BATS_TEST_TMPDIR/dl/go1.27.3.darwin-$ARCH.pkg.sha256"
  run run_fix fix_go_pkg 1.27.3
  [ "$status" -ne 0 ]
  [[ "$output" == *"not signed by Google"* ]] || false
  [ ! -e "$BATS_TEST_TMPDIR/installer-ran" ]
}
