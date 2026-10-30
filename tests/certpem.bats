#!/usr/bin/env bats
# The /etc/ssl/cert.pem fix follows Apple's steps (https://support.apple.com/en-us/149555):
# back up to cert.pem.orig, remove the root, install the file with mode 0644,
# check it with openssl, and back up again after a macOS update restored the file.
# Every test runs on a temporary copy, never on /etc/ssl/cert.pem.

load helpers/load
load helpers/certs

ECC="emSign ECC Root CA - G3"
AAA="AAA Certificate Services"

setup_file() {
  make_fillers "$BATS_FILE_TMPDIR"
}

setup() {
  load_script
  CERT="$BATS_TEST_TMPDIR/cert.pem"
  make_bundle "$CERT" "$BATS_FILE_TMPDIR/fillers.pem"
  cp -p "$CERT" "$BATS_TEST_TMPDIR/original.pem"
  use_certpem_file "$CERT"
}

@test "removing $ECC keeps the original as cert.pem.orig and leaves other roots" {
  run run_fix fix_certpem "$ECC"
  [ "$status" -eq 0 ]
  [ "$(bundle_roots "$CERT")" = "$AAA" ]
  grep -q "CN=emSign Root CA - G1$" "$CERT"
  cmp "$CERT.orig" "$BATS_TEST_TMPDIR/original.pem"
  [ "$(stat -f %Lp "$CERT")" = 644 ]
}

@test "removing $AAA afterwards keeps the first backup" {
  run run_fix fix_certpem "$ECC"
  [ "$status" -eq 0 ]
  run run_fix fix_certpem "$AAA"
  [ "$status" -eq 0 ]
  [ -z "$(bundle_roots "$CERT")" ]
  cmp "$CERT.orig" "$BATS_TEST_TMPDIR/original.pem"
}

@test "a file restored by a macOS update gets a fresh backup" {
  run run_fix fix_certpem "$ECC"
  [ "$status" -eq 0 ]
  # the update brings back the full file, with one certificate more than before
  make_bundle "$BATS_TEST_TMPDIR/updated.pem" "$BATS_FILE_TMPDIR/fillers.pem" 61
  cp "$BATS_TEST_TMPDIR/updated.pem" "$CERT"
  run run_fix fix_certpem "$ECC"
  [ "$status" -eq 0 ]
  cmp "$CERT.orig" "$BATS_TEST_TMPDIR/updated.pem"
  [ "$(bundle_roots "$CERT")" = "$AAA" ]
}

@test "a file openssl cannot read afterwards is put back as it was" {
  printf '### Broken\n\n=== /CN=broken\n-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n' >> "$CERT"
  cp -p "$CERT" "$BATS_TEST_TMPDIR/before.pem"
  run run_fix fix_certpem "$ECC"
  [ "$status" -ne 0 ]
  [[ "$output" == *"restored"* ]] || false
  cmp "$CERT" "$BATS_TEST_TMPDIR/before.pem"
}

@test "a bundle that would keep fewer than 50 certificates is not changed" {
  make_bundle "$CERT" "$BATS_FILE_TMPDIR/fillers.pem" 10
  cp -p "$CERT" "$BATS_TEST_TMPDIR/small.pem"
  run run_fix fix_certpem "$ECC"
  [ "$status" -ne 0 ]
  [[ "$output" == *"fewer than 50 certificates"* ]] || false
  cmp "$CERT" "$BATS_TEST_TMPDIR/small.pem"
}

@test "check_certpem shows Apple's steps and the backup name" {
  run check_certpem
  [[ "$output" == *"https://support.apple.com/en-us/149555"* ]] || false
  [[ "$output" == *"openssl crl2pkcs7 -nocrl -certfile"* ]] || false
  check_certpem >/dev/null
  [[ "${FX_LABEL[0]}" == *".orig"* ]] || false
}

@test "the macOS step and browser note use Apple's dates" {
  declare -f step_macos | grep -q "since 19 Oct 2026"
  declare -f step_macos | grep -q "emSign ECC Root CA - G3 since 23 Oct"
  declare -f check_browsers | grep -q "Apple since 19 Oct"
}
