#!/bin/bash
#
# fix-certpem.sh - Apple's steps for /etc/ssl/cert.pem after the eMudhra
# intermediate CA compromise (https://support.apple.com/en-us/149555).
#
#   Source : https://github.com/infraspecdev/emudhra-check
#
# /etc/ssl/cert.pem is the root list of Apple's built-in curl, git, python3,
# perl, ruby and openssl. This script removes the affected roots from it, the
# one change of the eMudhra fixes that is done as root by a separate script.
# It is kept small and separate from emudhra-check.sh so it can be read in full
# and given sudo on its own (a sudoers rule or MDM); emudhra-check.sh runs as
# your user, and its --fix runs this script with sudo.
#
# USAGE
#   sudo ./fix-certpem.sh              remove emSign ECC Root CA - G3 (and
#                                      emSign Root TLS CA - G3 if present)
#   sudo ./fix-certpem.sh --with-aaa   also remove AAA Certificate Services
#                                      (blocks the Sectigo cross-signed chains;
#                                      may break some unaffected sites)
#   sudo ./fix-certpem.sh "ROOT"...    remove only the named roots (one of the
#                                      three above)
#   ./fix-certpem.sh --check           list the affected roots still in the file
#                                      (no sudo needed)
#   sudo ./fix-certpem.sh --restore    put back the backup /etc/ssl/cert.pem.orig
#
# WHAT IT DOES (Apple's steps)
#   1. Backs up the file to /etc/ssl/cert.pem.orig, always a copy of Apple's
#      untouched file. A file that still has emSign ECC Root CA - G3 is
#      untouched, so it is backed up again: after a macOS update restored the
#      file, the old backup is out of date.
#   2. Removes each root, installs the result with mode 0644, owner root:wheel.
#   3. Checks it with openssl (Apple's step 4). If openssl cannot read it or
#      still lists the root, the file is put back as it was.
#   A result with fewer than 50 certificates is refused.
#   Repeat after every macOS update until Apple's own fix is installed.
#
# As root it only ever changes /etc/ssl/cert.pem and /etc/ssl/cert.pem.orig, and
# only removes the three roots above, whatever arguments it is given.
# Exit status: 0 done (or nothing to do), 1 failed, 2 usage error.
# --check: 0 when no emSign root is left, 1 otherwise.

set -u

ECC="emSign ECC Root CA - G3"
TLS="emSign Root TLS CA - G3"
AAA="AAA Certificate Services"

# The file. Tests (not root) may use a copy; as root it is always the real one.
if [ "$(id -u)" = 0 ]; then
  CERTPEM=/etc/ssl/cert.pem
  OWNER=(-o root -g wheel)
else
  CERTPEM=${FIX_CERTPEM_TEST_FILE:-/etc/ssl/cert.pem}
  OWNER=()
fi
BACKUP="$CERTPEM.orig"

usage() {
  echo "Usage: sudo $0 [--with-aaa] [\"ROOT\"...]   remove the affected roots from $CERTPEM"
  echo "       $0 --check                     list the affected roots still in it"
  echo "       sudo $0 --restore              put back $BACKUP"
  echo "ROOT is one of: \"$ECC\", \"$TLS\", \"$AAA\""
}

# has_root CN : the file contains the root whose subject ends in /CN=CN
has_root() { grep -q "^=== .*/CN=$1\$" "$CERTPEM"; }

# remove_root CN : Apple's steps for one root
remove_root() {
  local cn=$1 new prev listed
  if [ ! -f "$BACKUP" ] || has_root "$ECC"; then
    cp -p "$CERTPEM" "$BACKUP" || return 1
  fi
  new=$(mktemp) && prev=$(mktemp) || return 1
  cp -p "$CERTPEM" "$prev" || { rm -f "$new" "$prev"; return 1; }
  # filters the current file, so the roots can be removed one after the other
  awk -v m="/CN=$cn" '/^(###|===) / { skip = 0 }
       /^=== / && substr($0, length($0) - length(m) + 1) == m { skip = 1 }
       !skip' "$CERTPEM" > "$new" || { rm -f "$new" "$prev"; return 1; }
  if [ "$(grep -c 'BEGIN CERTIFICATE' "$new")" -lt 50 ]; then
    echo "The result has fewer than 50 certificates: $CERTPEM not changed."
    rm -f "$new" "$prev"
    return 1
  fi
  install -m 0644 ${OWNER[@]+"${OWNER[@]}"} "$new" "$CERTPEM" || { rm -f "$new" "$prev"; return 1; }
  # Apple's step 4: openssl must read the file and no longer list the root
  if listed=$(openssl crl2pkcs7 -nocrl -certfile "$CERTPEM" 2>/dev/null | openssl pkcs7 -print_certs -noout 2>/dev/null) \
     && ! printf '%s\n' "$listed" | grep -qF "$cn"; then
    echo "Removed $cn from $CERTPEM (backup: $BACKUP)"
    rm -f "$new" "$prev"
    return 0
  fi
  install -m 0644 ${OWNER[@]+"${OWNER[@]}"} "$prev" "$CERTPEM"
  echo "openssl could not verify $CERTPEM after removing $cn: restored it as it was."
  rm -f "$new" "$prev"
  return 1
}

check() {
  local cn left=0
  for cn in "$ECC" "$TLS" "$AAA"; do
    if has_root "$cn"; then
      echo "$CERTPEM still contains: $cn"
      [ "$cn" = "$AAA" ] || left=1
    fi
  done
  [ "$left" -eq 0 ] && echo "$CERTPEM does not contain the emSign roots."
  return "$left"
}

restore() {
  if [ ! -f "$BACKUP" ]; then echo "No backup $BACKUP: nothing to restore."; return 1; fi
  install -m 0644 ${OWNER[@]+"${OWNER[@]}"} "$BACKUP" "$CERTPEM" && echo "Restored $CERTPEM from $BACKUP"
}

main() {
  local roots=() cn mode=fix with_aaa=0 rc=0
  while [ $# -gt 0 ]; do
    case $1 in
      --check) mode=check ;;
      --restore) mode=restore ;;
      --with-aaa) with_aaa=1 ;;
      -h|--help) usage; return 0 ;;
      "$ECC"|"$TLS"|"$AAA") roots+=("$1") ;;
      *) echo "Unknown argument: $1" >&2; usage >&2; return 2 ;;
    esac
    shift
  done
  if [ ! -f "$CERTPEM" ]; then echo "$CERTPEM not found."; return 1; fi
  if [ "$mode" = check ]; then check; return; fi
  if [ "$(id -u)" != 0 ] && [ -z "${FIX_CERTPEM_TEST_FILE:-}" ]; then
    echo "This changes $CERTPEM and needs an admin password: sudo $0 $*" >&2
    return 1
  fi
  if [ "$mode" = restore ]; then restore; return; fi
  if [ ${#roots[@]} -eq 0 ]; then
    roots=("$ECC" "$TLS")
    [ "$with_aaa" = 1 ] && roots+=("$AAA")
  fi
  for cn in "${roots[@]}"; do
    if ! has_root "$cn"; then echo "$CERTPEM does not contain $cn."; continue; fi
    remove_root "$cn" || rc=1
  done
  return "$rc"
}

main "$@"
