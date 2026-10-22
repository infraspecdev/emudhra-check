#!/bin/bash
#
# emudhra-check.sh - read-only exposure check for the eMudhra intermediate CA
# compromise (October 2026) on macOS.
#
# Advisory: https://emudhra.we-have-a-problem.com/
#
# What it does
#   For every HTTPS client it finds on this Mac (curl, git, Python/pip, Node.js,
#   Java), it connects to the advisory's 12 TLS test hosts. A safe client must
#   REJECT all 12 with a certificate error, and must still connect to a normal
#   site. It also checks macOS updates, the Keychain, /etc/ssl/cert.pem,
#   Homebrew, tool versions against the advisory's "Who has patched?" table,
#   Electron apps, TLS-related settings, CA bundle files on disk and local
#   Docker images.
#
# What it does NOT do
#   It changes nothing on this Mac. It needs no sudo, git, Xcode or Homebrew.
#   The only file it writes is the log (see --log). If Docker is running, it
#   creates a stopped container per local image to read its CA file and removes
#   it right away (skip with --no-docker).
#
# Usage
#   curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash -s -- --quick
#   bash emudhra-check.sh [options]
#
# Source and documentation: https://github.com/wakumo/emudhra-check
#
# Options
#   --quick           Skip the slow steps (macOS update check, disk scan, Docker).
#   --no-scan         Skip the CA bundle file scan of the home folder.
#   --no-docker       Skip the Docker image check.
#   --deep            Also scan node_modules folders during the file scan.
#   --domain a,b      Also check that the certificates served by these domains
#                     do not use an affected intermediate (for service owners).
#   --log FILE        Write the log to FILE (default: ~/Desktop or ~).
#   --no-color        Plain output.
#   -h, --help        Show this help.
#
# Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = bad usage.

SCRIPT_VERSION="1.0.0 (2026-10-22)"

main() {

# ---------------------------------------------------------------------------
# Data from the advisory (https://github.com/galadran/we-have-a-problem.com)
# ---------------------------------------------------------------------------

# The 12 test hosts. Each serves a leaf signed by one compromised intermediate.
# *-emudhra     : intermediate <- emSign Root TLS CA - G3 <- emSign ECC Root CA - G3
# *-aaa-emudhra : intermediate cross-signed by AAA Certificate Services (Sectigo)
TEST_HOSTS="dv-g3b-emudhra.we-have-a-problem.com
ov-g3b-emudhra.we-have-a-problem.com
ev-g3b-emudhra.we-have-a-problem.com
dv-g3c-emudhra.we-have-a-problem.com
ov-g3c-emudhra.we-have-a-problem.com
ev-g3c-emudhra.we-have-a-problem.com
dv-g3b-aaa-emudhra.we-have-a-problem.com
ov-g3b-aaa-emudhra.we-have-a-problem.com
ev-g3b-aaa-emudhra.we-have-a-problem.com
dv-g3c-aaa-emudhra.we-have-a-problem.com
ov-g3c-aaa-emudhra.we-have-a-problem.com
ev-g3c-aaa-emudhra.we-have-a-problem.com"
# A normal site that every client must still reach.
CONTROL_HOST="github.com"
PIP_CONTROL_HOST="pypi.org"
# Overrides used only by the script's own test harness.
[ -n "$EMD_TEST_HOSTS" ] && TEST_HOSTS="$EMD_TEST_HOSTS"
[ -n "$EMD_CONTROL_HOST" ] && CONTROL_HOST="$EMD_CONTROL_HOST" && PIP_CONTROL_HOST="$EMD_CONTROL_HOST"
TEST_HOSTS=$(echo $TEST_HOSTS)          # one line, space separated
N_TEST=$(echo $TEST_HOSTS | wc -w | tr -d ' ')
ALL_HOSTS="$TEST_HOSTS $CONTROL_HOST"
# One host per root path, for slow clients (pip) that only read PEM bundles.
PIP_HOSTS="$(echo $TEST_HOSTS | awk '{print $1}') $(echo $TEST_HOSTS | awk '{print $NF}')"

# Two consecutive base64 lines from the PEM of each root (from roots.json).
# A PEM bundle that contains both lines contains that root.
ROOT_NAMES="AAA Certificate Services|emSign ECC Root CA - G3|emSign Root TLS CA - G3"
ROOT_L1_1="BwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM"
ROOT_L2_1="GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEP"
ROOT_L1_2="b2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw"
ROOT_L2_2="djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0"
ROOT_L1_3="VExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARfD9w/q1cWxL6D9bMG"
ROOT_L2_3="H6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8mWO/RwXQy10DCSxT8vSIJClHKp+Ao"

# SHA-256 of the 8 compromised intermediates and their 8 Sectigo cross-signs
# (impacted-intermediates.json).
BAD_SHA256="42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493
45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE
98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B
5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699
E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838
579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512
0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19
62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72
CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F
7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489
432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3
FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F
9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4
A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8
4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1
84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD"
BAD_CN_REGEX='EM (DV|OV|EV) TLS CA - G3[BC]|EM OV CS CA - G3[BC]'

# Patched versions ("Who has patched?" table on the advisory).
FIX_BREW_CA="2026-09-25_1"
FIX_CERTIFI="2026.10.19"
FIX_PIP="26.2.2"
FIX_UV="0.13.4"
FIX_PIXI="0.82.1"
FIX_RUSTUP="1.29.2"
FIX_DENO="2.9.8"
FIX_MISE="2026.10.17"
FIX_CLAUDE="2.1.303"
FIX_PERL_MOZCA="20261020"
FIX_NODE="22.23.4 24.22.1 26.12.1"            # newer majors are fine
FIX_GO="1.26.10 1.27.3"
FIX_ELECTRON="42.11.16 43.8.1 44.9.1"
FIX_JAVA="8.0.511 11.0.33 17.0.21 21.0.13 25.0.5 27.0.1"

ADVISORY="https://emudhra.we-have-a-problem.com/"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------
OPT_QUICK=0; OPT_SCAN=1; OPT_DOCKER=1; OPT_DEEP=0; OPT_DOMAINS=""; OPT_LOG=""; OPT_COLOR=1
while [ $# -gt 0 ]; do
  case "$1" in
    --quick) OPT_QUICK=1; OPT_SCAN=0; OPT_DOCKER=0 ;;
    --no-scan) OPT_SCAN=0 ;;
    --no-docker) OPT_DOCKER=0 ;;
    --deep) OPT_DEEP=1 ;;
    --domain|--domains) shift; OPT_DOMAINS="$1" ;;
    --domain=*|--domains=*) OPT_DOMAINS="${1#*=}" ;;
    --log) shift; OPT_LOG="$1" ;;
    --log=*) OPT_LOG="${1#*=}" ;;
    --no-color) OPT_COLOR=0 ;;
    -h|--help) sed -n '2,/^# Exit code/p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; return 0 ;;
    *) echo "Unknown option: $1 (try --help)"; return 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ $OPT_COLOR -eq 1 ] && [ -t 1 ]; then
  C_PASS=$'\033[32m'; C_FAIL=$'\033[31;1m'; C_WARN=$'\033[33m'; C_SKIP=$'\033[90m'
  C_INFO=$'\033[36m'; C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'
else
  C_PASS=""; C_FAIL=""; C_WARN=""; C_SKIP=""; C_INFO=""; C_BOLD=""; C_OFF=""
fi

if [ -z "$OPT_LOG" ]; then
  d="$HOME/Desktop"; [ -d "$d" ] && [ -w "$d" ] || d="$HOME"
  OPT_LOG="$d/emudhra-check-$(hostname -s 2>/dev/null || echo mac)-$(date +%Y%m%d-%H%M%S).log"
fi
LOG="$OPT_LOG"
: > "$LOG" 2>/dev/null || { LOG="/dev/null"; echo "Warning: cannot write log file $OPT_LOG"; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/emudhra-check.XXXXXX") || { echo "Cannot create temp dir"; return 1; }
trap 'rm -rf "$TMP"' EXIT
cd "$TMP" || return 1

# Results table (indexed arrays; macOS ships bash 3.2, no associative arrays)
R_N=0
R_STATUS=(); R_STEP=(); R_NAME=(); R_SECS=(); R_FIX=()
CUR_STEP=""; CUR_STEP_NO=0; TOTAL_STEPS=13

now_ms() {
  perl -MTime::HiRes=time -e 'printf("%d\n", time()*1000)' 2>/dev/null || echo "$(date +%s)000"
}
fmt_secs() { awk -v ms="$1" 'BEGIN { printf "%.1fs", ms/1000 }'; }
ts() { date +%H:%M:%S; }

# out <colored text> : prints to terminal and plain text to the log
out() {
  printf '%s\n' "$1"
  printf '%s\n' "$1" | sed $'s/\033\\[[0-9;]*m//g' >> "$LOG"
}
logonly() { printf '%s\n' "$1" >> "$LOG"; }

step() {
  CUR_STEP_NO=$((CUR_STEP_NO + 1))
  CUR_STEP="$1"
  STEP_T0=$(now_ms)
  out ""
  out "${C_BOLD}==> Step $CUR_STEP_NO/$TOTAL_STEPS: $1${C_OFF}   [$(ts)]"
  [ -n "$2" ] && out "    ${C_SKIP}$2${C_OFF}"
}
step_end() {
  local t1; t1=$(now_ms)
  out "    ${C_SKIP}-- step $CUR_STEP_NO finished in $(fmt_secs $((t1 - STEP_T0)))${C_OFF}"
}

# check_start : remember when the current check started
check_start() { CHK_T0=$(now_ms); }

# record STATUS "name" "detail" ["fix"]
# STATUS: PASS FAIL WARN SKIP INFO
record() {
  local st="$1" name="$2" detail="$3" fix="$4" t1 el col
  t1=$(now_ms); el=$((t1 - ${CHK_T0:-$t1})); CHK_T0=$t1
  case $st in
    PASS) col=$C_PASS ;; FAIL) col=$C_FAIL ;; WARN) col=$C_WARN ;; SKIP) col=$C_SKIP ;; *) col=$C_INFO ;;
  esac
  out "  [$(ts)] ${col}[$st]${C_OFF} $name${detail:+ - $detail}  ${C_SKIP}($(fmt_secs $el))${C_OFF}"
  if [ -n "$fix" ]; then
    printf '%s\n' "$fix" | while IFS= read -r l; do out "              ${C_BOLD}Fix:${C_OFF} $l"; done
  fi
  R_STATUS[$R_N]=$st; R_STEP[$R_N]=$CUR_STEP_NO; R_NAME[$R_N]="$name"
  R_SECS[$R_N]=$(fmt_secs $el); R_FIX[$R_N]="$fix"
  R_N=$((R_N + 1))
}

# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

# run_to SECONDS cmd... : run with a hard timeout (macOS has no `timeout`).
run_to() {
  local secs=$1 pid wpid rc; shift
  "$@" &
  pid=$!
  ( sleep "$secs"; kill -9 $pid ) >/dev/null 2>&1 &
  wpid=$!
  wait $pid 2>/dev/null; rc=$?
  kill $wpid >/dev/null 2>&1; wait $wpid 2>/dev/null
  return $rc
}

# resolve PATH : follow symlinks (no `realpath`/`readlink -f` on older macOS)
resolve() {
  local f="$1" d n=0
  while [ -L "$f" ] && [ $n -lt 40 ]; do
    d=$(dirname "$f"); f=$(readlink "$f")
    case "$f" in /*) ;; *) f="$d/$f" ;; esac
    n=$((n + 1))
  done
  d=$(cd -P "$(dirname "$f")" 2>/dev/null && pwd -P) || d=$(dirname "$f")
  echo "$d/$(basename "$f")"
}

# ver_ge A B : true if version A >= B (numeric fields, any separators)
ver_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    gsub(/^[^0-9]+/, "", a); gsub(/^[^0-9]+/, "", b)
    na = split(a, x, /[^0-9]+/); nb = split(b, y, /[^0-9]+/); n = (na > nb) ? na : nb
    for (i = 1; i <= n; i++) { p = x[i] + 0; q = y[i] + 0; if (p > q) exit 0; if (p < q) exit 1 }
    exit 0 }'
}
# major VERSION
major() { echo "$1" | sed 's/^[^0-9]*//' | awk -F'[^0-9]' '{print $1+0}'; }
# fixed_for_major VERSION "LIST" : prints the patched release of the same major, or nothing
fixed_for_major() {
  local m f; m=$(major "$1")
  for f in $2; do [ "$(major "$f")" = "$m" ] && { echo "$f"; return 0; }; done
  return 1
}
# max_major "LIST"
max_major() { local f m=0; for f in $1; do [ "$(major "$f")" -gt $m ] && m=$(major "$f"); done; echo $m; }

# patched_status VERSION "LIST" -> PASS / FAIL:<needed> (same major must be >= fix,
# majors newer than the newest fixed line are fine, other lines have no fix)
patched_status() {
  local v="$1" list="$2" f
  if f=$(fixed_for_major "$v" "$list"); then
    ver_ge "$v" "$f" && echo PASS || echo "FAIL:$f"
  elif [ "$(major "$v")" -gt "$(max_major "$list")" ]; then
    echo PASS
  else
    echo "FAIL:$(echo $list | tr ' ' '/')"
  fi
}

# bundle_roots FILE : prints the affected roots contained in a PEM file
bundle_roots() {
  local f="$1" i found="" name l1 l2
  [ -r "$f" ] || return 1
  for i in 1 2 3; do
    eval "l1=\$ROOT_L1_$i; l2=\$ROOT_L2_$i"
    if grep -qF "$l1" "$f" 2>/dev/null && grep -qF "$l2" "$f" 2>/dev/null; then
      name=$(echo "$ROOT_NAMES" | cut -d'|' -f$i)
      found="${found:+$found, }$name"
    fi
  done
  echo "$found"
}
cert_count() { local n; n=$(grep -c 'BEGIN CERTIFICATE' "$1" 2>/dev/null); echo "${n:-0}"; }

# Developer tools (Xcode / Command Line Tools). /usr/bin/git and
# /usr/bin/python3 are stubs that pop up an install dialog without them,
# so only use them when the tools are really installed.
DEV_DIR=""
if [ -x /usr/bin/xcode-select ]; then
  DEV_DIR=$(/usr/bin/xcode-select -p 2>/dev/null)
  [ -n "$DEV_DIR" ] && [ -d "$DEV_DIR" ] || DEV_DIR=""
fi

BREW_PREFIXES=""
for p in /opt/homebrew /usr/local; do
  [ -x "$p/bin/brew" ] && BREW_PREFIXES="$BREW_PREFIXES $p"
done

# candidates NAME paths... : unique existing executables, by resolved path
# uniq_bins < candidates (one path per line) : existing executables, unique by
# resolved path, version-manager shims removed
uniq_bins() {
  local b r seen="$TMP/seen.$RANDOM"
  : > "$seen"
  while IFS= read -r b; do
    [ -n "$b" ] && [ -x "$b" ] && [ ! -d "$b" ] || continue
    case "$b" in */shims/*|*/.volta/bin/*) continue ;; esac
    r=$(resolve "$b")
    grep -qxF "$r" "$seen" && continue
    echo "$r" >> "$seen"
    echo "$b"
  done
  rm -f "$seen"
}
path_bins() { type -ap "$1" 2>/dev/null; }

# ---------------------------------------------------------------------------
# Live TLS tests. Each tester prints lines "HOST ACCEPT|REJECT|NET detail".
# ACCEPT = TLS handshake succeeded (client trusts the chain)
# REJECT = certificate verification error (what we want for the test hosts)
# NET    = network/other error (inconclusive)
# ---------------------------------------------------------------------------

classify_msg() {   # generic stderr classifier for curl/git style messages
  if echo "$1" | grep -qiE 'certificate|issuer|self.signed|verify failed|not trusted|untrusted|SSL peer|unable to get local'; then
    echo REJECT
  elif echo "$1" | grep -qiE 'resolve|connect to|connection refused|timed out|timeout|network is unreachable|proxy|reset by peer|no route'; then
    echo NET
  else
    echo OTHER
  fi
}

t_curl_one() {   # BIN HOST
  local err rc st
  err=$("$1" -sS -o /dev/null --connect-timeout 8 --max-time 15 "https://$2/" 2>&1 </dev/null); rc=$?
  if [ $rc -eq 0 ]; then st=ACCEPT
  elif [ $rc -eq 60 ] || [ $rc -eq 77 ] || [ $rc -eq 83 ]; then st=REJECT
  elif [ $rc -eq 6 ] || [ $rc -eq 7 ] || [ $rc -eq 28 ] || [ $rc -eq 5 ]; then st=NET
  else st=$(classify_msg "$err"); [ "$st" = OTHER ] && st=NET
  fi
  echo "$2 $st rc=$rc $(echo "$err" | head -1 | cut -c1-160)"
}

t_git_one() {    # BIN HOST
  local err rc st
  err=$(GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/usr/bin/true run_to 25 "$1" \
        -c http.lowSpeedLimit=1 -c http.lowSpeedTime=15 \
        ls-remote "https://$2/emudhra-check.git" 2>&1 </dev/null); rc=$?
  if [ $rc -eq 0 ]; then st=ACCEPT
  else
    st=$(classify_msg "$err")
    # Any HTTP-level answer (404, "not found", "not valid") means TLS succeeded.
    [ "$st" = OTHER ] && st=ACCEPT
  fi
  echo "$2 $st $(echo "$err" | grep -v '^$' | tail -1 | cut -c1-160)"
}

# par_hosts FUNC BIN OUTFILE : run FUNC BIN HOST for all hosts in parallel
par_hosts() {
  local fn=$1 bin=$2 outf=$3 h i=0 pids=""
  for h in $ALL_HOSTS; do
    i=$((i + 1))
    "$fn" "$bin" "$h" > "$TMP/par.$i" 2>/dev/null &
    pids="$pids $!"
  done
  for p in $pids; do wait $p 2>/dev/null; done
  : > "$outf"
  i=0; for h in $ALL_HOSTS; do i=$((i + 1)); cat "$TMP/par.$i" >> "$outf" 2>/dev/null; done
}

cat > "$TMP/check_tls.py" <<'PYEOF'
import os, socket, ssl, sys
hosts = os.environ["EMD_HOSTS"].split()
VE = getattr(ssl, "SSLCertVerificationError", None)
ctxs = [("default", lambda: ssl.create_default_context())]
try:
    import certifi
    ctxs.append(("certifi", lambda: ssl.create_default_context(cafile=certifi.where())))
    print("#certifi %s %s" % (getattr(certifi, "__version__", "?"), certifi.where()))
except Exception:
    print("#certifi none -")
p = ssl.get_default_verify_paths()
print("#cafile %s" % (p.cafile or p.openssl_cafile))
print("#openssl %s" % ssl.OPENSSL_VERSION.replace(" ", "_"))
try:
    import pip
    print("#pip %s" % pip.__version__)
except Exception:
    print("#pip none")
print("#pipcert %s" % os.environ.get("PIP_CERT", "-"))
for name, mk in ctxs:
    for h in hosts:
        s = None
        try:
            ctx = mk()
            s = socket.create_connection((h, 443), timeout=10)
            t = ctx.wrap_socket(s, server_hostname=h)
            t.close()
            print("%s %s ACCEPT" % (name, h))
        except Exception as e:
            m = (type(e).__name__ + ": " + str(e)).replace("\n", " ")[:160]
            cert = (VE is not None and isinstance(e, VE)) or "CERTIFICATE_VERIFY_FAILED" in m \
                or "certificate verify failed" in m
            print("%s %s %s %s" % (name, h, "REJECT" if cert else "NET", m))
        finally:
            try:
                s and s.close()
            except Exception:
                pass
PYEOF

cat > "$TMP/check_tls.js" <<'JSEOF'
var tls = require('tls');
var hosts = process.env.EMD_HOSTS.split(' ');
var left = hosts.length;
var certErr = /^(CERT_|UNABLE_TO_|SELF_SIGNED_|DEPTH_ZERO_)/;
hosts.forEach(function (h) {
  var done = false, s;
  function fin(st, m) {
    if (done) return; done = true;
    console.log(h + ' ' + st + (m ? ' ' + String(m).replace(/\s+/g, ' ').slice(0, 160) : ''));
    try { s.destroy(); } catch (e) {}
    if (--left === 0) process.exit(0);
  }
  s = tls.connect({ host: h, port: 443, servername: h }, function () { fin('ACCEPT'); });
  s.setTimeout(10000, function () { fin('NET', 'timeout'); });
  s.on('error', function (e) { fin(certErr.test(e.code || '') ? 'REJECT' : 'NET', (e.code || '') + ' ' + e.message); });
});
setTimeout(function () { process.exit(0); }, 25000);
JSEOF

cat > "$TMP/EmudhraCheck.java" <<'JAVAEOF'
import java.net.InetSocketAddress;
import java.net.Socket;
import javax.net.ssl.*;

public class EmudhraCheck {
    public static void main(String[] args) {
        SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
        for (String h : args) {
            String r;
            Socket raw = new Socket();
            try {
                raw.connect(new InetSocketAddress(h, 443), 10000);
                raw.setSoTimeout(15000);
                SSLSocket s = (SSLSocket) f.createSocket(raw, h, 443, true);
                SSLParameters p = s.getSSLParameters();
                p.setEndpointIdentificationAlgorithm("HTTPS");
                s.setSSLParameters(p);
                s.startHandshake();
                s.close();
                r = "ACCEPT";
            } catch (SSLException e) {
                String m = String.valueOf(e.getMessage());
                boolean cert = m.contains("PKIX") || m.contains("ertificate") || m.contains("blocked")
                        || m.contains("Untrusted") || m.contains("certification path");
                r = (cert ? "REJECT " : "NET ") + e.getClass().getSimpleName() + ": " + m;
            } catch (Exception e) {
                r = "NET " + e;
            } finally {
                try { raw.close(); } catch (Exception e) { }
            }
            r = r.replace('\n', ' ');
            System.out.println(h + " " + (r.length() > 170 ? r.substring(0, 170) : r));
        }
    }
}
JAVAEOF

# judge FILE : summarise a tester's output into J_STATUS / J_DETAIL
judge() {
  local f="$1" h st rest acc=0 rej=0 net=0 acc_list="" first_net="" ctrl="" ctrl_d=""
  while read -r h st rest; do
    [ -z "$h" ] && continue
    if [ "$h" = "$CONTROL_HOST" ]; then ctrl="$st"; ctrl_d="$rest"; continue; fi
    case "$st" in
      ACCEPT) acc=$((acc + 1)); acc_list="$acc_list ${h%%.*}" ;;
      REJECT) rej=$((rej + 1)) ;;
      *) net=$((net + 1)); [ -z "$first_net" ] && first_net="$h: $rest" ;;
    esac
    logonly "              $h $st $rest"
  done < "$f"
  logonly "              $CONTROL_HOST (normal site) ${ctrl:-not tested} $ctrl_d"
  local total=$((acc + rej + net)) ctrl_txt
  J_CTRL_FAIL=0; [ -n "$ctrl" ] && [ "$ctrl" != ACCEPT ] && J_CTRL_FAIL=1
  if [ "$ctrl" = ACCEPT ]; then ctrl_txt="normal site $CONTROL_HOST OK"
  elif [ -n "$ctrl" ]; then ctrl_txt="normal site $CONTROL_HOST FAILED ($(echo "$ctrl_d" | cut -c1-90))"
  else ctrl_txt="normal site not tested"; fi
  if [ $total -eq 0 ]; then
    J_STATUS=WARN; J_DETAIL="no result (client did not run)"
  elif [ $acc -gt 0 ]; then
    J_STATUS=FAIL; J_DETAIL="TRUSTS $acc/$N_TEST compromised test chains:$acc_list"
  elif [ $rej -eq $N_TEST ]; then
    if [ "$ctrl" = ACCEPT ] || [ -z "$ctrl" ]; then
      J_STATUS=PASS; J_DETAIL="rejected $rej/$N_TEST test chains; $ctrl_txt"
    else
      J_STATUS=WARN; J_DETAIL="rejected $rej/$N_TEST test chains but $ctrl_txt"
    fi
  else
    J_STATUS=WARN; J_DETAIL="inconclusive: rejected $rej/$N_TEST, network errors $net/$N_TEST (first: $(echo "$first_net" | cut -c1-110))"
  fi
}

# ===========================================================================
# Header
# ===========================================================================
T_START=$(now_ms)
OS_NAME=$(sw_vers -productName 2>/dev/null || uname -s)
OS_VER=$(sw_vers -productVersion 2>/dev/null || uname -r)
OS_BUILD=$(sw_vers -buildVersion 2>/dev/null || echo "-")
out "${C_BOLD}eMudhra CA compromise - Mac exposure check v$SCRIPT_VERSION${C_OFF}"
out "Advisory : $ADVISORY"
out "Started  : $(date '+%Y-%m-%d %H:%M:%S %Z')"
out "Machine  : $(hostname -s 2>/dev/null) | $OS_NAME $OS_VER ($OS_BUILD) | $(uname -m) | user $(id -un)"
out "Log file : $LOG"
out "This script is read-only: it changes nothing on this Mac."
out "Statuses : PASS = safe | FAIL = must fix | WARN = could not decide or needs attention | SKIP = not installed / not run | INFO = for reference"
if [ "$(id -u)" = 0 ]; then
  out "${C_WARN}Note: running as root. Run it as your normal user so it checks your own tools and settings.${C_OFF}"
fi
if [ "$(uname -s)" != Darwin ]; then
  out "${C_WARN}Note: this is not macOS; macOS-specific checks will be skipped.${C_OFF}"
fi

# ===========================================================================
# Step 1: connectivity
# ===========================================================================
step "Connectivity to the advisory's test hosts" "Live checks need to reach the 12 test hosts on port 443."
check_start
reach=0; unreach=""
for h in $TEST_HOSTS; do
  if run_to 6 bash -c "exec 3<>/dev/tcp/$h/443" >/dev/null 2>&1; then reach=$((reach + 1)); else unreach="$unreach ${h%%.*}"; fi
done
if [ $reach -eq $N_TEST ]; then
  record PASS "Test hosts reachable" "$reach/$N_TEST reachable on TCP 443"
elif [ $reach -gt 0 ]; then
  record WARN "Test hosts reachable" "only $reach/$N_TEST reachable (not:$unreach); some live results will be inconclusive"
else
  record WARN "Test hosts reachable" "none reachable directly; live results will be inconclusive (offline, firewall or proxy-only network)"
fi
check_start
if [ -n "$HTTPS_PROXY$https_proxy$ALL_PROXY$all_proxy" ]; then
  record WARN "Proxy settings" "HTTPS proxy is set (${HTTPS_PROXY:-${https_proxy:-${ALL_PROXY:-$all_proxy}}}); curl/git/pip go through it, Python/Node/Java socket tests do not. A TLS-inspecting proxy can hide or change results."
else
  record PASS "Proxy settings" "no HTTPS proxy in environment"
fi
step_end

# ===========================================================================
# Step 2: macOS, browsers, Keychain, /etc/ssl/cert.pem
# ===========================================================================
step "macOS system trust" "Safari and native apps use the macOS trust store; Apple blocked the intermediates on 19 Oct 2026."
check_start
if [ "$(uname -s)" = Darwin ]; then
  if [ $OPT_QUICK -eq 1 ]; then
    record SKIP "macOS software updates" "skipped (--quick)"
  else
    upd=$(run_to 120 /usr/sbin/softwareupdate -l 2>&1 </dev/null)
    labels=$(echo "$upd" | grep -E '^[[:space:]]*\* (Label|Title):' | sed -E 's/^[[:space:]]*\* (Label|Title): *//' | head -5 | tr '\n' ';')
    if echo "$upd" | grep -qi 'No new software available'; then
      record PASS "macOS software updates" "$OS_NAME $OS_VER is up to date"
    elif [ -n "$labels" ]; then
      record FAIL "macOS software updates" "updates available: $labels" \
        "Install them: System Settings > General > Software Update, then restart."
    else
      record WARN "macOS software updates" "could not get the update list ($(echo "$upd" | tail -1 | cut -c1-100))" \
        "Check manually: System Settings > General > Software Update."
    fi
  fi
else
  record SKIP "macOS software updates" "not macOS"
fi

check_start
if have security; then
  kc_hits=""
  for cn in "EM DV TLS CA - G3" "EM OV TLS CA - G3" "EM EV TLS CA - G3" "EM OV CS CA - G3"; do
    hs=$(security find-certificate -a -Z -c "$cn" 2>/dev/null </dev/null | awk '/SHA-256 hash:/ {print $3}')
    for hsh in $hs; do
      echo "$BAD_SHA256" | grep -qxi "$hsh" && kc_hits="$kc_hits $cn($(echo "$hsh" | cut -c1-12))"
    done
  done
  trust=$( { security dump-trust-settings 2>/dev/null; security dump-trust-settings -d 2>/dev/null; } </dev/null \
           | grep -E "Cert [0-9]+:" | grep -E "$BAD_CN_REGEX|emSign|AAA Certificate Services")
  if [ -n "$trust" ]; then
    record FAIL "Keychain custom trust" "custom trust settings exist for: $(echo "$trust" | sed 's/.*: //' | tr '\n' ';')" \
      "Open Keychain Access, find these certificates, open Trust and set 'Use System Defaults' (or delete them)."
  else
    record PASS "Keychain custom trust" "no user/admin trust overrides for eMudhra/emSign/AAA certificates"
  fi
  check_start
  if [ -n "$kc_hits" ]; then
    record WARN "Keychain contents" "compromised intermediates stored in your keychains:$kc_hits" \
      "Not trusted by itself, but delete them in Keychain Access unless your IT team put them there."
  else
    record PASS "Keychain contents" "no compromised intermediates in login/System keychains"
  fi
else
  record SKIP "Keychain" "'security' tool not available (not macOS)"
fi

check_start
if [ -f /etc/ssl/cert.pem ]; then
  roots=$(bundle_roots /etc/ssl/cert.pem)
  if [ -n "$roots" ]; then
    record FAIL "/etc/ssl/cert.pem" "still contains: $roots. Used by Apple's built-in curl, git, python3, perl, ruby, openssl." \
"Advisory workaround (needs admin password; macOS updates may restore the file):
sudo cp -p /etc/ssl/cert.pem /etc/ssl/cert.pem.bak && sudo awk '/^(###|===) /{skip=0} /^=== .*\\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)\$/{skip=1} !skip' /etc/ssl/cert.pem.bak | sudo tee /etc/ssl/cert.pem > /dev/null"
  else
    record PASS "/etc/ssl/cert.pem" "does not contain the affected roots ($(cert_count /etc/ssl/cert.pem) certificates)"
  fi
else
  record SKIP "/etc/ssl/cert.pem" "file not found"
fi

check_start
br=""
for a in "/Applications/Safari.app" "/Applications/Google Chrome.app" "/Applications/Firefox.app" \
         "/Applications/Microsoft Edge.app" "/Applications/Brave Browser.app" "/Applications/Arc.app" \
         "/Applications/Opera.app" "/Applications/Vivaldi.app" "/Applications/Zen.app"; do
  [ -d "$a" ] || continue
  v=$(defaults read "$a/Contents/Info" CFBundleShortVersionString 2>/dev/null)
  br="$br $(basename "$a" .app) ${v:-?};"
done
if [ -n "$br" ]; then
  record INFO "Browsers" "${br# } (blocked via CRLSets/OneCRL/Apple since 17-19 Oct; just keep them updated and restart)"
else
  record SKIP "Browsers" "none found in /Applications"
fi
step_end

# ===========================================================================
# Step 3: curl
# ===========================================================================
step "curl" "Each curl binary must reject all $N_TEST test chains."
check_start
{ echo /usr/bin/curl; for p in $BREW_PREFIXES; do echo "$p/opt/curl/bin/curl"; done; path_bins curl; } | uniq_bins > "$TMP/list"
found=0
while IFS= read -r b; do
  found=1
  v=$("$b" --version 2>/dev/null </dev/null | head -1 | awk '{print $2, $NF}')
  par_hosts t_curl_one "$b" "$TMP/res"
  judge "$TMP/res"
  fix=""
  if [ $J_STATUS = FAIL ]; then
    case "$b" in
      /usr/bin/curl) fix="Apply the /etc/ssl/cert.pem fix from step 2 (macOS updates do not update that file)." ;;
      */homebrew/*|/usr/local/*) fix="brew update && brew upgrade ca-certificates curl" ;;
      *) fix="Update the CA bundle used by this curl (curl -V shows the build; see $ADVISORY)." ;;
    esac
  fi
  record $J_STATUS "curl $b ($v)" "$J_DETAIL" "$fix"
done < "$TMP/list"
[ $found -eq 0 ] && record SKIP "curl" "not found"
step_end

# ===========================================================================
# Step 4: git
# ===========================================================================
step "git" "git over HTTPS must reject all $N_TEST test chains."
check_start
{ [ -n "$DEV_DIR" ] && [ -x "$DEV_DIR/usr/bin/git" ] && echo /usr/bin/git
  for p in $BREW_PREFIXES; do echo "$p/bin/git"; done
  path_bins git | grep -vx /usr/bin/git; } | uniq_bins > "$TMP/list"
found=0
while IFS= read -r b; do
  found=1
  v=$("$b" --version 2>/dev/null </dev/null | awk '{print $3}')
  par_hosts t_git_one "$b" "$TMP/res"
  judge "$TMP/res"
  fix=""
  if [ $J_STATUS = FAIL ]; then
    case "$b" in
      /usr/bin/git) fix="Apply the /etc/ssl/cert.pem fix from step 2. Also check 'git config --global --get http.sslCAInfo'." ;;
      */homebrew/*|/usr/local/*) fix="brew update && brew upgrade ca-certificates git. Also check 'git config --global --get http.sslCAInfo'." ;;
      *) fix="Update the CA bundle this git uses ('git config --show-origin --get-regexp http.ssl')." ;;
    esac
  fi
  record $J_STATUS "git $b ($v)" "$J_DETAIL" "$fix"
done < "$TMP/list"
if [ $found -eq 0 ]; then
  if [ -z "$DEV_DIR" ]; then record SKIP "git" "not installed (no Xcode Command Line Tools, no Homebrew git)"
  else record SKIP "git" "not found"; fi
fi
step_end

# ===========================================================================
# Step 5: Python, certifi, pip
# ===========================================================================
step "Python, certifi and pip" "Tests Python's default SSL context, the certifi bundle (used by requests/httpx) and pip, per interpreter."
check_start
{ [ -n "$DEV_DIR" ] && [ -x "$DEV_DIR/usr/bin/python3" ] && echo /usr/bin/python3
  for p in $BREW_PREFIXES; do
    echo "$p/bin/python3"
    ls -d "$p"/opt/python@3*/bin/python3.* 2>/dev/null | grep -E 'python3\.[0-9]+$'
    echo "$p/Caskroom/miniconda/base/bin/python3"; echo "$p/Caskroom/miniforge/base/bin/python3"
  done
  ls -d /Library/Frameworks/Python.framework/Versions/*/bin/python3 \
        "$HOME"/.pyenv/versions/*/bin/python3 "$HOME"/.local/share/uv/python/*/bin/python3 \
        "$HOME"/.local/share/mise/installs/python/*/bin/python3 "$HOME"/.asdf/installs/python/*/bin/python3 2>/dev/null
  for c in miniconda3 anaconda3 miniforge3 mambaforge opt/anaconda3 opt/miniconda3; do echo "$HOME/$c/bin/python3"; done
  path_bins python3 | grep -vx /usr/bin/python3; } | uniq_bins > "$TMP/pylist"
found=0
while IFS= read -r py; do
  found=1
  check_start
  pv=$("$py" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null </dev/null)
  if [ -z "$pv" ]; then record WARN "python $py" "could not run it"; continue; fi
  EMD_HOSTS="$ALL_HOSTS" run_to 300 "$py" "$TMP/check_tls.py" > "$TMP/py.out" 2>"$TMP/py.err" </dev/null
  certifi_line=$(grep '^#certifi ' "$TMP/py.out"); certifi_v=$(echo "$certifi_line" | awk '{print $2}'); certifi_p=$(echo "$certifi_line" | awk '{print $3}')
  cafile=$(grep '^#cafile ' "$TMP/py.out" | cut -d' ' -f2-)
  osl=$(grep '^#openssl ' "$TMP/py.out" | cut -d' ' -f2 | tr '_' ' ')
  pipv=$(grep '^#pip ' "$TMP/py.out" | awk '{print $2}')
  logonly "              python $py: version $pv, $osl, default cafile=$cafile, certifi=$certifi_v $certifi_p, pip=$pipv"

  # 5a: default ssl context (urllib, http.client, aiohttp default...)
  grep '^default ' "$TMP/py.out" | cut -d' ' -f2- > "$TMP/res"
  judge "$TMP/res"
  fix=""
  if [ $J_STATUS = FAIL ]; then
    case "$cafile" in
      /etc/ssl/cert.pem|/private/etc/ssl/cert.pem) fix="This Python uses /etc/ssl/cert.pem: apply the fix from step 2." ;;
      */homebrew/*|/usr/local/*) fix="brew update && brew upgrade ca-certificates" ;;
      *) fix="Python uses $cafile; update that bundle (for python.org builds: upgrade certifi and run 'Install Certificates.command')." ;;
    esac
  fi
  if [ $J_STATUS = WARN ] && [ "$J_CTRL_FAIL" = 1 ]; then
    fix="This Python cannot verify normal sites either. python.org builds: run 'Install Certificates.command' in /Applications/Python 3.x/."
  fi
  record $J_STATUS "python $pv ($py) ssl default" "$J_DETAIL" "$fix"

  # 5b: certifi
  check_start
  if [ "$certifi_v" = none ] || [ -z "$certifi_v" ]; then
    record SKIP "python $pv certifi" "certifi not installed for this interpreter"
  else
    grep '^certifi ' "$TMP/py.out" | cut -d' ' -f2- > "$TMP/res"
    judge "$TMP/res"
    fix=""
    croots=$(bundle_roots "$certifi_p")
    if [ $J_STATUS = FAIL ] || [ -n "$croots" ]; then
      fix="\"$py\" -m pip install --upgrade 'certifi>=$FIX_CERTIFI'   (Homebrew Python: brew upgrade python-certifi; also upgrade it in each virtualenv)"
      if [ $J_STATUS != FAIL ]; then J_STATUS=FAIL; J_DETAIL="bundle still contains: $croots; $J_DETAIL"; fi
    elif ! ver_ge "$certifi_v" "$FIX_CERTIFI"; then
      J_DETAIL="$J_DETAIL; version older than $FIX_CERTIFI but its bundle has no affected roots"
    fi
    record $J_STATUS "python $pv certifi $certifi_v" "$J_DETAIL" "$fix"
  fi

  # 5c: pip (real download attempt against one host per root path)
  check_start
  if [ "$pipv" = none ] || [ -z "$pipv" ]; then
    record SKIP "python $pv pip" "pip not installed for this interpreter"
  else
    : > "$TMP/res"
    for h in $PIP_HOSTS $PIP_CONTROL_HOST; do
      po=$(PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 run_to 60 "$py" -m pip download --no-deps --no-cache-dir \
            --retries 0 --timeout 10 -d "$TMP/pipdl" --index-url "https://$h/simple/" \
            emudhra-check-nonexistent-probe 2>&1 </dev/null)
      if echo "$po" | grep -qiE 'CERTIFICATE_VERIFY_FAILED|SSLCertVerificationError|confirming the ssl certificate|certificate verify failed|SSLError'; then st=REJECT
      elif echo "$po" | grep -qiE 'Could not find a version|No matching distribution'; then st=ACCEPT
      else st=NET; fi
      hh=$h; [ "$h" = "$PIP_CONTROL_HOST" ] && hh=$CONTROL_HOST
      echo "$hh $st $(echo "$po" | grep -iE 'error|warning' | head -1 | cut -c1-140)" >> "$TMP/res"
    done
    N_SAVE=$N_TEST; N_TEST=2
    judge "$TMP/res"
    N_TEST=$N_SAVE
    J_DETAIL=$(echo "$J_DETAIL" | sed "s/normal site $CONTROL_HOST/normal index $PIP_CONTROL_HOST/")
    fix=""
    if [ $J_STATUS = FAIL ]; then
      if [ "$py" = /usr/bin/python3 ]; then
        fix="Built-in pip uses its own old copy of the roots. After the step 2 fix, run (advisory):
F=\"\$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path(\"stdlib\"))')/sitecustomize.py\" && echo 'import os; os.environ.setdefault(\"PIP_CERT\", \"/etc/ssl/cert.pem\")' | sudo tee -a \"\$F\" > /dev/null && sudo chmod 644 \"\$F\""
      else
        fix="\"$py\" -m pip install --upgrade 'pip>=$FIX_PIP'"
      fi
    elif ! ver_ge "$pipv" "$FIX_PIP" && [ $J_STATUS = PASS ]; then
      J_DETAIL="$J_DETAIL (pip $pipv < $FIX_PIP but this setup already rejects)"
    fi
    record $J_STATUS "python $pv pip $pipv" "$J_DETAIL (tested 1 host per root)" "$fix"
  fi
done < "$TMP/pylist"
[ $found -eq 0 ] && record SKIP "Python" "no Python 3 found (Apple's python3 needs Command Line Tools)"
step_end

# ===========================================================================
# Step 6: Node.js
# ===========================================================================
step "Node.js" "Node ships its own root list. Patched: $FIX_NODE (newer majors are fine)."
check_start
{ for p in $BREW_PREFIXES; do echo "$p/bin/node"; ls -d "$p"/opt/node@*/bin/node 2>/dev/null; done
  ls -d "$HOME"/.nvm/versions/node/*/bin/node \
        "$HOME/Library/Application Support/fnm/node-versions"/*/installation/bin/node \
        "$HOME"/.local/share/fnm/node-versions/*/installation/bin/node "$HOME"/.fnm/node-versions/*/installation/bin/node \
        "$HOME"/.volta/tools/image/node/*/bin/node "$HOME"/.asdf/installs/nodejs/*/bin/node \
        "$HOME"/.local/share/mise/installs/node/*/bin/node 2>/dev/null
  echo /usr/local/bin/node; path_bins node; } | uniq_bins > "$TMP/list"
found=0
while IFS= read -r nb; do
  found=1
  check_start
  nv=$("$nb" --version 2>/dev/null </dev/null | tr -d 'v')
  [ -z "$nv" ] && { record WARN "node $nb" "could not run it"; continue; }
  EMD_HOSTS="$ALL_HOSTS" run_to 60 "$nb" "$TMP/check_tls.js" > "$TMP/res" 2>/dev/null </dev/null
  judge "$TMP/res"
  ps=$(patched_status "$nv" "$FIX_NODE")
  fix=""
  [ "$ps" != PASS ] && J_DETAIL="$J_DETAIL; version $nv is not a patched release (need ${ps#FAIL:})"
  if [ $J_STATUS = FAIL ]; then
    fix="Upgrade Node to a patched release (${ps#FAIL:}; newer majors are fine). Temporary workaround: NODE_OPTIONS=--use-system-ca"
  elif [ "$ps" != PASS ] && [ $J_STATUS = PASS ]; then
    J_STATUS=WARN
    fix="Upgrade Node to ${ps#FAIL:} or newer. It passes here only because of your current settings (NODE_OPTIONS='$NODE_OPTIONS')."
  fi
  record $J_STATUS "node $nv ($nb)" "$J_DETAIL" "$fix"
done < "$TMP/list"
[ $found -eq 0 ] && record SKIP "Node.js" "not installed"
step_end

# ===========================================================================
# Step 7: Java
# ===========================================================================
step "Java" "Each JDK/JRE must reject all $N_TEST test chains. Patched: Java $FIX_JAVA (8.0.511 = 8u511)."
check_start
JHS=""
if [ -x /usr/libexec/java_home ]; then
  JHS=$(/usr/libexec/java_home -V 2>&1 </dev/null | grep -E '^ +[0-9]' | awk '{print $NF}')
fi
JHS="$JHS
$(ls -d $HOME/.sdkman/candidates/java/* 2>/dev/null | grep -v '/current$')
$(ls -d $HOME/Library/Java/JavaVirtualMachines/*/Contents/Home 2>/dev/null)
$(ls -d $HOME/.asdf/installs/java/* $HOME/.local/share/mise/installs/java/* 2>/dev/null)"
for p in $BREW_PREFIXES; do JHS="$JHS
$(ls -d $p/opt/openjdk*/libexec/openjdk.jdk/Contents/Home 2>/dev/null)"; done
JHS="$JHS
$(ls -d /Applications/*.app/Contents/jbr/Contents/Home 2>/dev/null)
$(ls -d /Applications/*.app/Contents/jre/Contents/Home 2>/dev/null)"
[ -n "$JAVA_HOME" ] && JHS="$JHS
$JAVA_HOME"
: > "$TMP/jh"
found=0
echo "$JHS" | while IFS= read -r jh; do
  [ -n "$jh" ] || continue
  [ -x "$jh/bin/java" ] || { [ -x "$jh/Contents/Home/bin/java" ] && jh="$jh/Contents/Home"; }
  [ -x "$jh/bin/java" ] || continue
  r=$(cd -P "$jh" 2>/dev/null && pwd -P)
  grep -qxF "$r" "$TMP/jh" || echo "$r" >> "$TMP/jh"
done
while IFS= read -r jh; do
  [ -n "$jh" ] || continue
  found=1
  check_start
  jv=$("$jh/bin/java" -version 2>&1 </dev/null | grep -m1 ' version "' | sed -E 's/.*version "([^"]*)".*/\1/')
  [ -n "$jv" ] || jv="unknown"
  jvn=$(echo "$jv" | sed -E 's/^1\.8\.0_([0-9]+).*/8.0.\1/; s/^1\.([0-9]+).*/\1/')
  bc=""
  for f in "$jh/lib/security/blocked.certs" "$jh/jre/lib/security/blocked.certs"; do [ -f "$f" ] && bc="$f"; done
  nb=0
  if [ -n "$bc" ]; then for s in $BAD_SHA256; do grep -qi "$s" "$bc" && nb=$((nb + 1)); done; fi
  ps=$(patched_status "$jvn" "$FIX_JAVA")
  : > "$TMP/res"
  if [ "$(major "$jvn")" -ge 11 ]; then
    run_to 120 "$jh/bin/java" "$TMP/EmudhraCheck.java" $ALL_HOSTS > "$TMP/res" 2>"$TMP/java.err" </dev/null
  fi
  if [ -s "$TMP/res" ]; then
    judge "$TMP/res"
  else
    # Java 8, or a runtime without the compiler (IDE runtimes): decide statically.
    if [ $nb -eq 16 ] || [ "$ps" = PASS ]; then J_STATUS=PASS; J_DETAIL="static check (no live test possible): patched version or all fingerprints blocked"
    else J_STATUS=FAIL; J_DETAIL="static check (no live test possible): version $jv not patched"; fi
  fi
  J_DETAIL="$J_DETAIL; blocked.certs has $nb/16 fingerprints"
  fix=""
  if [ $J_STATUS = FAIL ]; then
    fix="Upgrade this JDK to a patched release (${ps#FAIL:}), or add the 16 SHA-256 fingerprints from impacted-intermediates.json to $jh/lib/security/blocked.certs. Do not delete roots from cacerts."
  elif [ "$ps" != PASS ] && [ $J_STATUS = PASS ]; then
    J_DETAIL="$J_DETAIL; version $jv older than ${ps#FAIL:} but this JDK already rejects"
  fi
  record $J_STATUS "java $jv ($jh)" "$J_DETAIL" "$fix"
done < "$TMP/jh"
[ -s "$TMP/jh" ] || record SKIP "Java" "no JDK/JRE installed"
step_end

# ===========================================================================
# Step 8: other tools with their own CA bundle (version checks)
# ===========================================================================
step "Other tools with built-in CA lists" "Version check against the advisory's 'Who has patched?' table. Not installed = SKIP."

# vcheck NAME BIN VERSION_CMD... ; compares to FIXVAR
vcheck() {
  local name="$1" fixv="$2" bin="$3" howfix="$4" v
  check_start
  if [ -z "$bin" ] || ! [ -x "$bin" ]; then record SKIP "$name" "not installed"; return; fi
  v=$(run_to 20 "$bin" --version 2>/dev/null </dev/null | head -1 | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)
  if [ -z "$v" ]; then record WARN "$name ($bin)" "could not read version"; return; fi
  if ver_ge "$v" "$fixv"; then record PASS "$name $v ($bin)" "patched (>= $fixv)"
  else record FAIL "$name $v ($bin)" "older than patched $fixv" "$howfix"; fi
}
firstbin() { local b; for b in "$@"; do [ -x "$b" ] && { echo "$b"; return; }; done; }

check_start
bca=""
for p in $BREW_PREFIXES; do
  for d in "$p/Cellar/ca-certificates"/*; do [ -d "$d" ] && bca="$(basename "$d")"; done
done
if [ -z "$BREW_PREFIXES" ]; then
  record SKIP "Homebrew ca-certificates" "Homebrew not installed"
elif [ -z "$bca" ]; then
  record SKIP "Homebrew ca-certificates" "formula not installed"
elif ver_ge "$bca" "$FIX_BREW_CA"; then
  record PASS "Homebrew ca-certificates $bca" "patched (>= $FIX_BREW_CA)"
else
  record FAIL "Homebrew ca-certificates $bca" "older than patched $FIX_BREW_CA" "brew update && brew upgrade ca-certificates"
fi
for p in $BREW_PREFIXES; do
  for f in "$p/etc/ca-certificates/cert.pem" "$p/etc/openssl@3/cert.pem" "$p/etc/openssl@1.1/cert.pem" "$p/etc/openssl/cert.pem"; do
    [ -f "$f" ] || continue
    check_start
    roots=$(bundle_roots "$f")
    if [ -n "$roots" ]; then record FAIL "Homebrew bundle $f" "still contains: $roots" "brew update && brew upgrade ca-certificates && brew postinstall ca-certificates"
    else record PASS "Homebrew bundle $f" "affected roots not present"; fi
  done
done

vcheck "uv" "$FIX_UV" "$(firstbin $(path_bins uv) $HOME/.local/bin/uv $HOME/.cargo/bin/uv)" "uv self update   (or: brew upgrade uv)"
vcheck "pixi" "$FIX_PIXI" "$(firstbin $(path_bins pixi) $HOME/.pixi/bin/pixi)" "pixi self-update"
vcheck "rustup" "$FIX_RUSTUP" "$(firstbin $(path_bins rustup) $HOME/.cargo/bin/rustup)" "rustup self update"
vcheck "deno" "$FIX_DENO" "$(firstbin $(path_bins deno) $HOME/.deno/bin/deno)" "deno upgrade"
vcheck "mise" "$FIX_MISE" "$(firstbin $(path_bins mise) $HOME/.local/bin/mise)" "mise self-update   (or: brew upgrade mise)"
vcheck "Claude Code" "$FIX_CLAUDE" "$(firstbin $(path_bins claude) $HOME/.claude/local/claude $HOME/.local/bin/claude)" "claude update"

check_start
bunb=$(firstbin $(path_bins bun) $HOME/.bun/bin/bun)
if [ -n "$bunb" ]; then
  record WARN "bun $("$bunb" --version 2>/dev/null </dev/null)" "no patched release yet (advisory: pending)" "Watch https://github.com/oven-sh/bun/pull/46159 and upgrade when released."
else
  record SKIP "bun" "not installed"
fi

check_start
gob=$(firstbin $(path_bins go) /usr/local/go/bin/go)
if [ -n "$gob" ]; then
  gv=$("$gob" version 2>/dev/null </dev/null | awk '{print $3}' | sed 's/^go//')
  ps=$(patched_status "$gv" "$FIX_GO")
  if [ "$ps" = PASS ]; then
    record PASS "go $gv" "patched (>= $FIX_GO)"
  else
    record WARN "go $gv" "not a patched release (need ${ps#FAIL:}). Go programs on macOS use the system verifier, but binaries you build for Linux/Docker embed the old list." \
      "Upgrade Go and rebuild binaries/images you ship."
  fi
else
  record SKIP "go" "not installed"
fi

check_start
{ echo /usr/bin/perl; for p in $BREW_PREFIXES; do echo "$p/bin/perl"; done; } | uniq_bins > "$TMP/list"
pfound=0
while IFS= read -r pb; do
  mv=$("$pb" -MMozilla::CA -e 'print $Mozilla::CA::VERSION' 2>/dev/null </dev/null)
  [ -n "$mv" ] || continue
  pfound=1
  check_start
  if ver_ge "$mv" "$FIX_PERL_MOZCA"; then record PASS "Perl Mozilla::CA $mv ($pb)" "patched"
  else record FAIL "Perl Mozilla::CA $mv ($pb)" "older than $FIX_PERL_MOZCA" "cpan Mozilla::CA   (or update the package that installed it)"; fi
done < "$TMP/list"
[ $pfound -eq 0 ] && record SKIP "Perl Mozilla::CA" "not installed"
step_end

# ===========================================================================
# Step 9: Electron apps
# ===========================================================================
step "Electron apps (Slack, VS Code, Discord, ...)" "Electron embeds Node's root list. Patched Electron: $FIX_ELECTRON (newer majors are fine)."
check_start
efound=0
for app in /Applications/*.app /Applications/*/*.app "$HOME"/Applications/*.app; do
  fw="$app/Contents/Frameworks/Electron Framework.framework"
  [ -d "$fw" ] || continue
  efound=1
  check_start
  an=$(basename "$app" .app)
  av=$(defaults read "$app/Contents/Info" CFBundleShortVersionString 2>/dev/null)
  ev=""
  for pl in "$fw/Resources/Info.plist" "$fw/Versions/A/Resources/Info.plist" "$fw/Versions/Current/Resources/Info.plist"; do
    [ -f "$pl" ] && ev=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$pl" 2>/dev/null) && [ -n "$ev" ] && break
  done
  if [ -z "$ev" ]; then
    record WARN "$an ${av}" "Electron app, could not read Electron version" "Update the app to its latest version."
    continue
  fi
  ps=$(patched_status "$ev" "$FIX_ELECTRON")
  if [ "$ps" = PASS ]; then
    record PASS "$an $av" "Electron $ev is patched"
  else
    record FAIL "$an $av" "Electron $ev is not patched (need ${ps#FAIL:})" "Update $an (app menu > Check for Updates). If it is already the latest version, the vendor has not shipped a fix yet: check again later."
  fi
done
[ $efound -eq 0 ] && record SKIP "Electron apps" "none found in /Applications"
step_end

# ===========================================================================
# Step 10: settings that disable verification or point to custom bundles
# ===========================================================================
step "TLS settings in your environment" "Checks variables/configs that turn off verification or point to a custom CA bundle."
check_start
bad_env=""
[ "$NODE_TLS_REJECT_UNAUTHORIZED" = 0 ] && bad_env="$bad_env NODE_TLS_REJECT_UNAUTHORIZED=0;"
[ "$PYTHONHTTPSVERIFY" = 0 ] && bad_env="$bad_env PYTHONHTTPSVERIFY=0;"
[ -n "$GIT_SSL_NO_VERIFY" ] && bad_env="$bad_env GIT_SSL_NO_VERIFY;"
[ -f "$HOME/.curlrc" ] && grep -qE '^[[:space:]]*(-k|--insecure|insecure)([[:space:]]|$)' "$HOME/.curlrc" && bad_env="$bad_env ~/.curlrc insecure;"
[ -f "$HOME/.npmrc" ] && grep -qE '^[[:space:]]*strict-ssl[[:space:]]*=[[:space:]]*false' "$HOME/.npmrc" && bad_env="$bad_env ~/.npmrc strict-ssl=false;"
[ -f "$HOME/.gitconfig" ] && grep -qiE '^[[:space:]]*sslverify[[:space:]]*=[[:space:]]*false' "$HOME/.gitconfig" && bad_env="$bad_env ~/.gitconfig http.sslVerify=false;"
for pc in "$HOME/.config/pip/pip.conf" "$HOME/Library/Application Support/pip/pip.conf" "$HOME/.pip/pip.conf"; do
  [ -f "$pc" ] && grep -qiE '^[[:space:]]*trusted-host' "$pc" && bad_env="$bad_env $pc trusted-host;"
done
if [ -n "$bad_env" ]; then
  record FAIL "Certificate verification disabled" "$bad_env" "Remove these settings. Never disable certificate verification (advisory)."
else
  record PASS "Certificate verification disabled" "no settings found that turn verification off"
fi

cfiles=""
for v in SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO PIP_CERT; do
  eval "val=\$$v"; [ -n "$val" ] && cfiles="$cfiles
$v=$val"
done
[ -f "$HOME/.gitconfig" ] && val=$(awk -F= 'tolower($1) ~ /sslcainfo/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' "$HOME/.gitconfig" | head -1) && [ -n "$val" ] && cfiles="$cfiles
git http.sslCAInfo=$val"
[ -f "$HOME/.npmrc" ] && val=$(awk -F= '$1 ~ /^[ \t]*cafile/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' "$HOME/.npmrc" | head -1) && [ -n "$val" ] && cfiles="$cfiles
npm cafile=$val"
check_start
if [ -z "$cfiles" ]; then
  record PASS "Custom CA bundle settings" "none set (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, NODE_EXTRA_CA_CERTS, GIT_SSL_CAINFO, PIP_CERT, git sslCAInfo, npm cafile)"
else
  printf '%s\n' "$cfiles" > "$TMP/cfiles"
  while IFS= read -r kv; do
    [ -n "$kv" ] || continue
    check_start
    f="${kv#*=}"; f="${f/#\~/$HOME}"
    if [ ! -f "$f" ]; then record WARN "Custom CA bundle: $kv" "file not found"; continue; fi
    roots=$(bundle_roots "$f")
    if [ -n "$roots" ]; then
      record FAIL "Custom CA bundle: $kv" "contains: $roots" "Replace it with an updated bundle, or remove the setting. Do not use bundles copied before 20 Oct 2026."
    else
      record PASS "Custom CA bundle: $kv" "affected roots not present"
    fi
  done < "$TMP/cfiles"
fi
step_end

# ===========================================================================
# Step 11: CA bundle files on disk
# ===========================================================================
step "CA bundle files on disk" "Finds PEM bundles (certifi in virtualenvs, vendored copies...) that still contain the affected roots."
check_start
if [ $OPT_SCAN -eq 0 ]; then
  record SKIP "CA bundle scan" "skipped (--quick/--no-scan)"
else
  NAMES='( -name cacert.pem -o -name cert.pem -o -name ca-bundle.crt -o -name ca-bundle.pem -o -name ca-certificates.crt -o -name cacerts.pem -o -name tls-ca-bundle.pem -o -name ca-root-nss.crt )'
  prune_nm='-name node_modules -prune -o'
  [ $OPT_DEEP -eq 1 ] && prune_nm=""
  out "    scanning home folder and tool folders (this can take a minute)..."
  {
    run_to 240 find "$HOME" -xdev \( -path "$HOME/Library" -o -path "$HOME/.Trash" -o -path "$HOME/.cache" \
      -o -path "$HOME/Pictures" -o -path "$HOME/Movies" -o -path "$HOME/Music" -o -name .git \) -prune -o \
      $prune_nm -type f $NAMES -print 2>/dev/null
    for d in "$HOME/Library/Python" $BREW_PREFIXES /Library/Frameworks/Python.framework /opt/local /opt/anaconda3 /opt/miniconda3; do
      [ -d "$d" ] && run_to 120 find "$d" \( -name .git -o -path "*/Homebrew/Library" \) -prune -o -type f $NAMES -print 2>/dev/null
    done
  } </dev/null | sort -u > "$TMP/bundles"
  nb_total=0; nb_bad=0; nb_clean=0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ "$(cert_count "$f")" -ge 20 ] || continue          # ignore single certs / test fixtures
    nb_total=$((nb_total + 1))
    roots=$(bundle_roots "$f")
    if [ -n "$roots" ]; then
      nb_bad=$((nb_bad + 1))
      check_start
      case "$f" in
        */pip/_vendor/certifi/*) fx="This is pip's vendored copy: upgrade pip in that environment (pip >= $FIX_PIP)." ;;
        */site-packages/certifi/*)
          envp=$(echo "$f" | sed -E 's#/lib/python[0-9.]+/site-packages/certifi/.*##')
          fx="\"$envp/bin/python\" -m pip install --upgrade 'certifi>=$FIX_CERTIFI'   (delete the environment if unused)" ;;
        */Cellar/*|*/homebrew/*) fx="brew update && brew upgrade" ;;
        *) fx="Update the software that ships this file (or ignore if unused)." ;;
      esac
      record FAIL "Bundle $f" "contains: $roots" "$fx"
    else
      nb_clean=$((nb_clean + 1))
      logonly "              clean bundle: $f"
    fi
  done < "$TMP/bundles"
  check_start
  if [ $nb_total -eq 0 ]; then
    record PASS "CA bundle scan" "no PEM CA bundles found"
  elif [ $nb_bad -eq 0 ]; then
    record PASS "CA bundle scan" "$nb_total bundle(s) checked, none contain the affected roots (list in log)"
  else
    record INFO "CA bundle scan" "$nb_total bundle(s) checked: $nb_bad still contain affected roots (FAIL lines above), $nb_clean clean"
  fi
fi
step_end

# ===========================================================================
# Step 12: Docker images
# ===========================================================================
step "Docker images" "Containers carry their own CA bundle; updating the Mac does not update them."
check_start
if [ $OPT_DOCKER -eq 0 ]; then
  record SKIP "Docker images" "skipped (--quick/--no-docker)"
elif ! have docker; then
  record SKIP "Docker images" "docker not installed"
elif ! run_to 15 docker info >/dev/null 2>&1 </dev/null; then
  record SKIP "Docker images" "Docker is installed but not running"
else
  docker image ls --format '{{.ID}} {{.Repository}}:{{.Tag}}' 2>/dev/null </dev/null | grep -v '<none>' \
    | awk '!seen[$1]++' | head -60 > "$TMP/images"
  n_img=$(wc -l < "$TMP/images" | tr -d ' ')
  [ "$n_img" -eq 0 ] && record SKIP "Docker images" "no local images"
  while read -r iid iname; do
    [ -n "$iid" ] || continue
    check_start
    cid=$(run_to 30 docker create "$iid" /emudhra-check-noop 2>/dev/null </dev/null)
    if [ -z "$cid" ]; then record WARN "image $iname" "could not create a stopped container to inspect it"; continue; fi
    got=""
    for p in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem \
             /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/cert.pem; do
      if run_to 30 docker cp -L "$cid:$p" - 2>/dev/null </dev/null | tar -xOf - > "$TMP/img.pem" 2>/dev/null && [ -s "$TMP/img.pem" ]; then
        got="$p"; break
      fi
    done
    docker rm -f "$cid" >/dev/null 2>&1 </dev/null
    if [ -z "$got" ]; then
      record WARN "image $iname" "no system CA bundle found (scratch/custom image?)" "Check how this image's app verifies TLS."
      continue
    fi
    roots=$(bundle_roots "$TMP/img.pem")
    if [ -n "$roots" ]; then
      record FAIL "image $iname" "$got contains: $roots" "Rebuild on an updated base image (apt-get/apk/dnf upgrade ca-certificates), push and redeploy."
    else
      record PASS "image $iname" "$got does not contain the affected roots (OS bundle only; app-level bundles inside are not checked)"
    fi
  done < "$TMP/images"
fi
step_end

# ===========================================================================
# Step 13: domains you serve (optional)
# ===========================================================================
step "Certificates served by your domains" "Only with --domain. Fails if a served chain uses an affected intermediate."
check_start
if [ -z "$OPT_DOMAINS" ]; then
  record SKIP "Served certificates" "no --domain given"
elif ! have openssl; then
  record SKIP "Served certificates" "openssl not found"
else
  for d in $(echo "$OPT_DOMAINS" | tr ',' ' '); do
    check_start
    hp="$d"; case "$d" in *:*) ;; *) hp="$d:443" ;; esac
    chain=$(echo | run_to 20 openssl s_client -connect "$hp" -servername "${d%%:*}" -showcerts 2>/dev/null)
    if ! echo "$chain" | grep -q 'BEGIN CERTIFICATE'; then
      record WARN "Served chain $d" "could not fetch the certificate chain"; continue
    fi
    names=$(echo "$chain" | grep -E '^ *[0-9]+ s:|^ *i:' | tr '\n' ' ')
    if echo "$names" | grep -qE "$BAD_CN_REGEX"; then
      record FAIL "Served chain $d" "uses an affected eMudhra intermediate" "Replace this certificate with one from an unaffected CA and redeploy."
    else
      record PASS "Served chain $d" "no affected intermediate ($(echo "$chain" | grep -E '^ *0 s:' | head -1 | sed 's/^ *0 s://' | cut -c1-60))"
    fi
  done
fi
step_end

# ===========================================================================
# Summary
# ===========================================================================
T_END=$(now_ms)
n_pass=0; n_fail=0; n_warn=0; n_skip=0
i=0
while [ $i -lt $R_N ]; do
  case ${R_STATUS[$i]} in PASS) n_pass=$((n_pass+1));; FAIL) n_fail=$((n_fail+1));; WARN) n_warn=$((n_warn+1));; SKIP) n_skip=$((n_skip+1));; esac
  i=$((i + 1))
done
out ""
out "${C_BOLD}================================ SUMMARY ================================${C_OFF}"
out "Finished : $(date '+%Y-%m-%d %H:%M:%S %Z') (total $(fmt_secs $((T_END - T_START))))"
out "Results  : ${C_PASS}$n_pass PASS${C_OFF}, ${C_FAIL}$n_fail FAIL${C_OFF}, ${C_WARN}$n_warn WARN${C_OFF}, $n_skip SKIP"
out ""
out "$(printf '%-4s %-6s %-5s %-8s %s' '#' 'STATUS' 'STEP' 'TIME' 'CHECK')"
i=0
while [ $i -lt $R_N ]; do
  st=${R_STATUS[$i]}
  case $st in PASS) col=$C_PASS;; FAIL) col=$C_FAIL;; WARN) col=$C_WARN;; SKIP) col=$C_SKIP;; *) col=$C_INFO;; esac
  out "$(printf '%-4s %s%-6s%s %-5s %-8s %s' $((i + 1)) "$col" "$st" "$C_OFF" "${R_STEP[$i]}" "${R_SECS[$i]}" "${R_NAME[$i]}")"
  i=$((i + 1))
done
if [ $n_fail -gt 0 ] || [ $n_warn -gt 0 ]; then
  out ""
  out "${C_BOLD}What to do:${C_OFF}"
  i=0
  while [ $i -lt $R_N ]; do
    st=${R_STATUS[$i]}
    if { [ "$st" = FAIL ] || [ "$st" = WARN ]; } && [ -n "${R_FIX[$i]}" ]; then
      out "  [$st] #$((i + 1)) ${R_NAME[$i]}"
      printf '%s\n' "${R_FIX[$i]}" | while IFS= read -r l; do out "        $l"; done
    fi
    i=$((i + 1))
  done
  out ""
  out "After fixing, restart the affected apps/terminals and run this script again."
fi
out ""
if [ $n_fail -gt 0 ]; then
  out "${C_FAIL}RESULT: NOT OK - $n_fail item(s) still trust the compromised eMudhra intermediates or need updates.${C_OFF}"
else
  if [ $n_warn -gt 0 ]; then
    out "${C_PASS}RESULT: OK - no FAIL found.${C_OFF} Review the $n_warn WARN item(s) above."
  else
    out "${C_PASS}RESULT: OK - no FAIL found.${C_OFF}"
  fi
fi
out "Full log (send this file if asked): $LOG"
[ $n_fail -gt 0 ] && return 1
return 0
}

# Everything is inside main() so the script also works when piped into bash
# (curl ... | bash): stdin is closed for all commands it runs.
main "$@" </dev/null
exit $?
