# shellcheck shell=bash
# Test helpers for certificate bundles in Apple's /etc/ssl/cert.pem format.

# make_fillers DIR : 60 throwaway self-signed certificates in DIR/fillers.pem,
# each under its own "### " and "=== " lines like Apple's file (slow, so tests
# call it once from setup_file)
make_fillers() {
  local dir=$1 i
  for i in $(seq 1 60); do
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
      -subj "/CN=filler-$i" -keyout "$dir/key.pem" -out "$dir/cert-$i.pem" 2>/dev/null || return 1
    printf '### Filler %s\n\n=== /CN=filler-%s\n' "$i" "$i" >> "$dir/fillers.pem"
    cat "$dir/cert-$i.pem" >> "$dir/fillers.pem"
    rm -f "$dir/cert-$i.pem"
  done
  rm -f "$dir/key.pem"
}

# make_bundle OUT FILLERS_FILE [N] : the fixture roots (AAA Certificate Services,
# emSign ECC Root CA - G3, emSign Root CA - G1) plus the first N fillers (default 60)
make_bundle() {
  local out=$1 fillers=$2 n=${3:-60}
  cp "$REPO/tests/fixtures/apple-roots.pem" "$out"
  awk -v n="$n" '/^### / { c++ } c <= n' "$fillers" >> "$out"
}

# use_certpem_file FILE : redefine fix_certpem and check_certpem to work on FILE
# instead of /etc/ssl/cert.pem, without the root:wheel ownership (tests do not run as root)
use_certpem_file() {
  local f=$1 fn
  for fn in fix_certpem check_certpem; do
    eval "$(declare -f "$fn" | sed -e "s#/etc/ssl/cert.pem#$f#g" -e 's/ -o root -g wheel//g')"
  done
}
