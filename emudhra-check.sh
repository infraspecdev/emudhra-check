#!/bin/bash
#
# emudhra-check.sh - checks a Mac for exposure to the eMudhra intermediate CA
# compromise (October 2026) and, only if asked, fixes what it can.
#
#   Advisory : https://emudhra.we-have-a-problem.com/
#   Source   : https://github.com/wakumo/emudhra-check
#
# WHAT IT DOES
#   Finds the HTTPS clients on this Mac (the macOS trust store, curl, git,
#   Python/pip, Node.js, Java) and makes each one connect to the advisory's
#   14 TLS test hosts. A safe client refuses all 14 with a certificate error
#   and still connects to a normal site. It also compares tool versions with
#   the advisory's "Who has patched?" table and looks for CA bundle files that
#   still contain the affected root certificates.
#
# WHAT IT READS
#   Program versions, Keychain trust settings, `softwareupdate -l`, TLS-related
#   environment variables and ~/.curlrc, ~/.npmrc, ~/.gitconfig, pip.conf.
#   It searches the home folder for CA bundle files by name (cacert.pem,
#   ca-bundle.crt, ...) and reads only those. It reads no passwords, keys,
#   documents or browser data.
#
# WHAT IT CONNECTS TO
#   Port 443 of the 14 *.we-have-a-problem.com test hosts, github.com and
#   pypi.org (normal sites), plus any --domain you pass. Nothing is uploaded:
#   results stay in the terminal and in the log file.
#
# WHAT IT CHANGES
#   Check mode (the default): nothing. It writes its log file and a temporary
#   folder with the small probe programs (section "Probe programs"), which is
#   deleted at exit. If Docker is running, it creates a stopped container per local image
#   to read its CA file, and removes it right away (skip with --no-docker).
#   --fix: shows the list of fixes and asks before running any of them. Every
#   change it can make is one fix_* function in the section "Automatic fixes",
#   which also says how to undo it. Some fixes run the tools' own updaters (brew, pip, uv,
#   rustup...), which download from their usual sources.
#
# Usage
#   curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash
#   bash emudhra-check.sh --help
#
# Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = bad usage.
#
# CONTENTS (each section starts with a "# ====" banner)
#   Advisory data          test hosts, root markers, the 16 fingerprints, patched versions
#   Options, run state     --help text, option parsing, temporary folder
#   Output                 terminal and log formatting, record() for each result
#   Generic helpers        versions, paths, certificate files
#   Probe programs         the 4 small Python/Node.js/Java/JXA test programs
#   Live TLS tests         one tester per client, judge() sums up the results
#   Automatic fixes        every change --fix can make (fix_* functions)
#   Step 1 ... Step 13     one function per check step
#   Header and summary
#   Main                   the order of the steps, entry point

# The step and fix functions are called through the STEPS list and add_fix.
# shellcheck disable=SC2329
SCRIPT_VERSION="1.4.0 (2026-10-29)"

# ===========================================================================
# Advisory data (from https://github.com/galadran/we-have-a-problem.com)
# ===========================================================================
ADVISORY="https://emudhra.we-have-a-problem.com/"
SCRIPT_URL="https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh"

# The 12 test hosts. Each serves a leaf signed by one compromised intermediate.
#   *-emudhra     : intermediate <- emSign Root TLS CA - G3 <- emSign ECC Root CA - G3
#   *-aaa-emudhra : intermediate cross-signed by AAA Certificate Services (Sectigo)
ADVISORY_TEST_HOSTS=(
  dv-g3b-emudhra.we-have-a-problem.com     ov-g3b-emudhra.we-have-a-problem.com
  ev-g3b-emudhra.we-have-a-problem.com     dv-g3c-emudhra.we-have-a-problem.com
  ov-g3c-emudhra.we-have-a-problem.com     ev-g3c-emudhra.we-have-a-problem.com
  dv-g3b-aaa-emudhra.we-have-a-problem.com ov-g3b-aaa-emudhra.we-have-a-problem.com
  ev-g3b-aaa-emudhra.we-have-a-problem.com dv-g3c-aaa-emudhra.we-have-a-problem.com
  ov-g3c-aaa-emudhra.we-have-a-problem.com ev-g3c-aaa-emudhra.we-have-a-problem.com
)
# The 2 "No CT" test hosts (added 22 Oct): their leaf was never logged to
# Certificate Transparency, so CT-enforcing clients reject it even if they trust
# the intermediate. Accepting one means the client can be attacked unnoticed.
ADVISORY_NOCT_HOSTS=(
  dv-g3b-noct-emudhra.we-have-a-problem.com dv-g3b-aaa-noct-emudhra.we-have-a-problem.com
)
# Normal sites that every client must still reach.
ADVISORY_CONTROL_HOST="github.com"
ADVISORY_PIP_CONTROL_HOST="pypi.org"

# The affected roots, each identified by two consecutive base64 lines of its
# PEM (from roots.json): a PEM bundle that contains both lines contains that root.
ROOT_NAMES=("AAA Certificate Services" "emSign ECC Root CA - G3" "emSign Root TLS CA - G3")
ROOT_L1=(BwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMM
         b2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMw
         VExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARfD9w/q1cWxL6D9bMG)
ROOT_L2=(GEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEP
         djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0
         H6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8mWO/RwXQy10DCSxT8vSIJClHKp+Ao)

# SHA-256 fingerprints of the 8 compromised intermediates and their 8 Sectigo
# cross-signs (impacted-intermediates.json).
BAD_SHA256=(
  42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493
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
  84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD
)
# Subject names of the compromised intermediates
BAD_CN_REGEX='EM (DV|OV|EV) TLS CA - G3[BC]|EM OV CS CA - G3[BC]'

# Patched versions ("Who has patched?" table on the advisory)
FIX_BREW_CA="2026-09-25_1"
FIX_CERTIFI="2026.10.19"
FIX_PIP="26.2.2"
FIX_UV="0.13.5"
FIX_PIXI="0.82.1"
FIX_RUSTUP="1.29.2"
FIX_DENO="2.9.8"
FIX_MISE="2026.10.17"
FIX_CLAUDE="2.1.303"
FIX_PERL_MOZCA="20261020"
FIX_NODE="22.23.4 24.22.1 26.12.1"            # one per release line; newer majors are fine
FIX_GO="1.26.10 1.27.3"
FIX_ELECTRON="42.11.16 43.8.1 44.9.1"
FIX_JAVA="8.0.511 11.0.33 17.0.21 21.0.13 25.0.5 27.0.1"   # Oracle JDK only; OpenJDK is pending
FIX_BUN="1.4.4"
FIX_GH="2.102.1"
FIX_DOCKER="29.9.2"                            # Docker CLI and Docker Engine
FIX_DOCKER_DESKTOP="4.96.2"
# ===========================================================================
# Options, run state, temporary folder
# ===========================================================================

usage() {
  cat <<'EOF'
eMudhra CA compromise - Mac exposure check

Usage
  curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash
  curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash -s -- --fix
  bash emudhra-check.sh [options]

Default: check only (dry-run). Changes nothing on this Mac.

Options
  --fix             After the checks, list the automatic fixes, ask once, apply
                    them (asks for your password if a fix needs it), re-check.
  --yes             With --fix: do not ask for confirmation (for MDM/scripts).
                    Optional fixes are then skipped unless --with-optional.
  --with-optional   With --fix: also apply the optional fixes without asking
                    (removing AAA Certificate Services from /etc/ssl/cert.pem).
  --quick           Skip the slow steps (macOS update check, disk scan, Docker).
  --no-scan         Skip the CA bundle file scan of the home folder.
  --no-docker       Skip the Docker image check.
  --deep            Also scan node_modules folders during the file scan.
  --domain a,b      Also check that the certificates served by these domains
                    do not use an affected intermediate (for service owners).
  --log FILE        Write the log to FILE (default: ~/Desktop or ~).
  --no-color        Plain output.
  -h, --help        Show this help.

Exit code: 0 = no FAIL, 1 = at least one FAIL, 2 = bad usage.
Source and documentation: https://github.com/wakumo/emudhra-check
EOF
}

# parse_options ARGS... : sets the OPT_* variables; returns 1 on a bad option
parse_options() {
  OPT_FIX=0; OPT_YES=0; OPT_OPTIONAL=0; OPT_AFTER_FIX=0; OPT_HELP=0
  OPT_QUICK=0; OPT_SCAN=1; OPT_DOCKER=1; OPT_DEEP=0
  OPT_DOMAINS=""; OPT_LOG=""; OPT_COLOR=1
  while [ $# -gt 0 ]; do
    case "$1" in
      --fix) OPT_FIX=1 ;;
      --check|--dry-run) OPT_FIX=0 ;;
      --yes|-y) OPT_YES=1 ;;
      --with-optional) OPT_OPTIONAL=1 ;;
      --after-fix) OPT_AFTER_FIX=1 ;;           # internal: the re-check after --fix
      --quick) OPT_QUICK=1; OPT_SCAN=0; OPT_DOCKER=0 ;;
      --no-scan) OPT_SCAN=0 ;;
      --no-docker) OPT_DOCKER=0 ;;
      --deep) OPT_DEEP=1 ;;
      --domain|--domains) shift; OPT_DOMAINS="$1" ;;
      --domain=*|--domains=*) OPT_DOMAINS="${1#*=}" ;;
      --log) shift; OPT_LOG="$1" ;;
      --log=*) OPT_LOG="${1#*=}" ;;
      --no-color) OPT_COLOR=0 ;;
      -h|--help) OPT_HELP=1 ;;
      *) echo "Unknown option: $1 (try --help)"; return 1 ;;
    esac
    shift
  done
}

# init_state : reset everything a run collects (main runs twice after --fix)
init_state() {
  # Test hosts (EMD_* overrides are used only by the script's own test harness)
  if [ -n "$EMD_TEST_HOSTS" ]; then
    read -r -a TEST_HOSTS <<< "$EMD_TEST_HOSTS"
  else
    TEST_HOSTS=("${ADVISORY_TEST_HOSTS[@]}")
  fi
  CONTROL_HOST="${EMD_CONTROL_HOST:-$ADVISORY_CONTROL_HOST}"
  PIP_CONTROL_HOST="${EMD_CONTROL_HOST:-$ADVISORY_PIP_CONTROL_HOST}"
  # pip is slow: one test host per root path (the first is direct, the last cross-signed)
  PIP_HOSTS=("${TEST_HOSTS[0]}" "${TEST_HOSTS[$((${#TEST_HOSTS[@]} - 1))]}")
  [ -z "$EMD_TEST_HOSTS" ] && TEST_HOSTS+=("${ADVISORY_NOCT_HOSTS[@]}")
  N_TEST=${#TEST_HOSTS[@]}
  ALL_HOSTS=("${TEST_HOSTS[@]}" "$CONTROL_HOST")

  # Results, one entry per check (bash 3.2 on macOS: indexed arrays only)
  R_N=0; R_STATUS=(); R_STEP=(); R_NAME=(); R_SECS=(); R_FIX=()
  N_PASS=0; N_FAIL=0; N_WARN=0; N_SKIP=0
  CUR_STEP_NO=0; TOTAL_STEPS=${#STEPS[@]}; STEP_TITLE=(); STEP_SECS=()

  # Fixes registered by the checks (see "Automatic fixes")
  FX_N=0; FX_SUDO=(); FX_LABEL=(); FX_ARGS=(); FX_OPT=(); BREW_FORMULAS=""; PYFIX_SEEN=""
  EMD_RERUN=0

  # Facts from step 2 that later steps use
  SWU_PID=""; SCAN_PID=""
  SWU_IMPORTANT=""     # pending macOS/Safari/security updates, ";" separated
  MAC_UPTODATE=0       # 1 = softwareupdate says nothing is pending
  CERTPEM_CLEAN=0      # 1 = /etc/ssl/cert.pem has no affected root
  SYS_TESTED=0         # 1 = the macOS trust store was tested live
  SYS_ACC=""           # test hosts the macOS trust store accepts
  SYS_FIX="macOS itself still trusts these chains (see step 2 'macOS trust store') and this tool asks macOS, so nothing to change in the tool. Install the pending macOS/Safari updates (System Settings > General > Software Update) and restart."
}

# init_workdir : private temporary folder for the probe programs and results.
# It is the working directory during the run (so no tool picks up files from
# the folder you started in), and it is deleted when the script exits.
init_workdir() {
  if [ -n "$EMD_TMP" ] && [ -d "$EMD_TMP" ]; then cd / && rm -rf "$EMD_TMP"; fi
  EMD_TMP=$(mktemp -d "${TMPDIR:-/tmp}/emudhra-check.XXXXXX") || { echo "Cannot create a temporary folder"; return 1; }
  trap 'cd / && rm -rf "$EMD_TMP"' EXIT
  cd "$EMD_TMP" || return 1
}

# detect_environment : developer tools and Homebrew prefixes
detect_environment() {
  local p
  # /usr/bin/git and /usr/bin/python3 are stubs that pop up an install dialog
  # without Xcode or the Command Line Tools: use them only when those exist.
  DEV_DIR=""
  if [ -x /usr/bin/xcode-select ]; then
    DEV_DIR=$(/usr/bin/xcode-select -p 2>/dev/null)
    [ -n "$DEV_DIR" ] && [ -d "$DEV_DIR" ] || DEV_DIR=""
  fi
  BREW_PREFIXES=()
  for p in /opt/homebrew /usr/local; do
    [ -x "$p/bin/brew" ] && BREW_PREFIXES+=("$p")
  done
  OS_NAME=$(sw_vers -productName 2>/dev/null || uname -s)
  OS_VER=$(sw_vers -productVersion 2>/dev/null || uname -r)
  OS_BUILD=$(sw_vers -buildVersion 2>/dev/null || echo "-")
  IS_MAC=0; [ "$(uname -s)" = Darwin ] && IS_MAC=1
}
# ===========================================================================
# Output: terminal and log file
# ===========================================================================
# On a color terminal (PRETTY=1) the screen gets a compact view with icons.
# The log file always gets the plain, complete format (grep-friendly).

# init_output : colors, screen width and the log file
init_output() {
  local d
  if [ "$OPT_COLOR" -eq 1 ] && [ -t 1 ]; then
    C_PASS=$'\033[32m'; C_FAIL=$'\033[31;1m'; C_WARN=$'\033[33m'; C_SKIP=$'\033[90m'
    C_INFO=$'\033[36m'; C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'
    PRETTY=1
    # Icons and cutting to the screen width need a UTF-8 locale (the macOS
    # Terminal default). With no locale at all, use UTF-8 for this shell only.
    if [ -z "$LC_ALL$LC_CTYPE$LANG" ]; then { LC_CTYPE=en_US.UTF-8; } 2>/dev/null; fi
    case "${LC_ALL:-${LC_CTYPE:-$LANG}}" in *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) ;; *) PRETTY=0 ;; esac
  else
    C_PASS=""; C_FAIL=""; C_WARN=""; C_SKIP=""; C_INFO=""; C_BOLD=""; C_OFF=""
    PRETTY=0
  fi

  TERM_W=""
  [ "$PRETTY" -eq 1 ] && TERM_W=$(stty size </dev/tty 2>/dev/null | awk '{print $2}')
  case "$TERM_W" in ''|*[!0-9]*) TERM_W=$(tput cols 2>/dev/null) ;; esac
  case "$TERM_W" in ''|*[!0-9]*) TERM_W=100 ;; esac
  [ "$TERM_W" -lt 70 ] && TERM_W=70
  [ "$TERM_W" -gt 150 ] && TERM_W=150
  RULE_W=$TERM_W; [ "$RULE_W" -gt 92 ] && RULE_W=92

  if [ -z "$OPT_LOG" ]; then
    d="$HOME/Desktop"; [ -d "$d" ] && [ -w "$d" ] || d="$HOME"
    OPT_LOG="$d/emudhra-check-$(hostname -s 2>/dev/null || echo mac)-$(date +%Y%m%d-%H%M%S).log"
  fi
  LOG="$OPT_LOG"
  [ "$OPT_AFTER_FIX" -eq 1 ] && LOG="${LOG%.log}-after-fix.log"
  : > "$LOG" 2>/dev/null || { LOG="/dev/null"; echo "Warning: cannot write log file $OPT_LOG"; }
}

now_ms() {
  perl -MTime::HiRes=time -e 'printf("%d\n", time()*1000)' 2>/dev/null || echo "$(date +%s)000"
}
fmt_secs() { awk -v ms="$1" 'BEGIN { printf "%.1fs", ms/1000 }'; }
ts() { date +%H:%M:%S; }

# out TEXT : terminal (with colors) and log (without)
out() {
  printf '%s\n' "$1"
  printf '%s\n' "$1" | sed $'s/\033\\[[0-9;]*m//g' >> "$LOG"
}
# logonly TEXT : log only
logonly() { printf '%s\n' "$1" >> "$LOG"; }
# scr TEXT : terminal only, pretty mode only
scr() { [ "$PRETTY" -eq 1 ] && printf '%s\n' "$1"; return 0; }
# plain TEXT : log; also the terminal when not in pretty mode
plain() { if [ "$PRETTY" -eq 1 ]; then logonly "$1"; else out "$1"; fi; }

# icon STATUS : single-codepoint emoji (always 2 cells wide, so columns line up)
icon() {
  case $1 in
    PASS|DONE) printf '%s' "✅" ;; FAIL|FAILED) printf '%s' "❌" ;; WARN) printf '%s' "🟡" ;;
    SKIP) printf '%s' "⚪" ;; RUN) printf '%s' "⏳" ;; *) printf '%s' "🔵" ;;
  esac
}
# stcol STATUS : color of a status word
stcol() {
  case $1 in
    PASS|DONE) printf '%s' "$C_PASS" ;; FAIL|FAILED) printf '%s' "$C_FAIL" ;; WARN) printf '%s' "$C_WARN" ;;
    SKIP) printf '%s' "$C_SKIP" ;; *) printf '%s' "$C_INFO" ;;
  esac
}
# tilde TEXT : $HOME shown as ~ (screen only)
tilde() { local t='~'; printf '%s' "${1//"$HOME"/$t}"; }
# fit TEXT WIDTH : cut to WIDTH characters with an ellipsis
fit() {
  if [ ${#1} -gt "$2" ]; then printf '%s…' "${1:0:$(($2 - 1))}"; else printf '%s' "$1"; fi
}
# fitm TEXT WIDTH : cut in the middle, keeping the end (paths end with the useful part)
fitm() {
  local h t
  if [ ${#1} -gt "$2" ]; then
    h=$(($2 / 3)); t=$(($2 - h - 1))
    printf '%s…%s' "${1:0:$h}" "${1:$((${#1} - t))}"
  else
    printf '%s' "$1"
  fi
}
# padr TEXT N : TEXT padded with spaces to N characters (printf pads bytes)
padr() { local k=$(($2 - ${#1})); printf '%s' "$1"; [ "$k" -gt 0 ] && printf "%${k}s" ''; return 0; }
# rule TITLE [RIGHT] : "━━ TITLE ━━━━━━━━━━━ RIGHT" across the screen
rule() {
  local left="━━ $1 " right="${2:+ $2}" n line
  n=$((RULE_W - ${#left} - ${#right}))
  [ "$n" -lt 3 ] && n=3
  line=$(printf '%*s' $n '' | sed 's/ /━/g')
  printf '%s%s%s%s%s%s\n' "$C_BOLD" "$left" "$line" "$C_OFF" "$C_SKIP" "$right$C_OFF"
}

# ---------------------------------------------------------------------------
# Steps and results
# ---------------------------------------------------------------------------
# step "title" ["what it checks"] : start the next step
step() {
  CUR_STEP_NO=$((CUR_STEP_NO + 1))
  STEP_T0=$(now_ms)
  STEP_TITLE[CUR_STEP_NO]="$1"; STEP_SECS[CUR_STEP_NO]="-"
  plain ""
  plain "==> Step $CUR_STEP_NO/$TOTAL_STEPS: $1   [$(ts)]"
  [ -n "$2" ] && plain "    $2"
  scr ""
  scr "$(rule "$CUR_STEP_NO/$TOTAL_STEPS  $1" "$(ts)")"
  [ -n "$2" ] && scr "   ${C_SKIP}$(fit "$2" $((TERM_W - 4)))${C_OFF}"
  check_start
}
step_end() {
  local t1; t1=$(now_ms)
  STEP_SECS[CUR_STEP_NO]=$(fmt_secs $((t1 - STEP_T0)))
  plain "    -- step $CUR_STEP_NO finished in ${STEP_SECS[$CUR_STEP_NO]}"
  scr "   ${C_SKIP}└ step done in ${STEP_SECS[$CUR_STEP_NO]}${C_OFF}"
}

# check_start : the next record measures its time from now
check_start() { CHK_T0=$(now_ms); }

# record STATUS "name" "detail" ["fix"] : print and store one result.
# STATUS is PASS, FAIL, WARN, SKIP or INFO; "fix" tells the user what to do.
record() {
  local st="$1" name="$2" detail="$3" fix="$4" t1 el col txt tm dim="" l
  t1=$(now_ms); el=$((t1 - ${CHK_T0:-$t1})); CHK_T0=$t1
  tm=$(fmt_secs "$el")
  plain "  [$(ts)] [$st] $name${detail:+ - $detail}  ($tm)"
  [ -n "$fix" ] && printf '%s\n' "$fix" | while IFS= read -r l; do plain "              Fix: $l"; done
  if [ "$PRETTY" -eq 1 ]; then
    col=$(stcol "$st")
    # the screen line is cut to the terminal width; the log has it all
    txt=$(fit "$(tilde "$name")${detail:+ · $(tilde "$detail")}" $((TERM_W - 13 - ${#tm})))
    case $st in SKIP|INFO|PASS) dim=$C_SKIP ;; esac
    case "$txt" in
      *" · "*) txt="${txt%%" · "*}${dim:-$C_SKIP} · ${C_OFF}${dim}${txt#*" · "}" ;;
    esac
    printf '  %s %s%-4s%s  %s%s  %s%s%s\n' "$(icon "$st")" "$col" "$st" "$C_OFF" "$txt" "$C_OFF" "$C_SKIP" "$tm" "$C_OFF"
    [ -n "$fix" ] && printf '%s\n' "$fix" | while IFS= read -r l; do
      printf '           %s↳%s %s\n' "$C_WARN" "$C_OFF" "$l"
    done
  fi
  R_STATUS+=("$st"); R_STEP+=("$CUR_STEP_NO"); R_NAME+=("$name"); R_SECS+=("$tm"); R_FIX+=("$fix")
  R_N=${#R_STATUS[@]}
}
# ===========================================================================
# Generic helpers
# ===========================================================================

have() { command -v "$1" >/dev/null 2>&1; }

# firstbin PATH... : the first one that is an executable
firstbin() { local b; for b in "$@"; do [ -x "$b" ] && { echo "$b"; return; }; done; }
# path_bins NAME : every NAME on $PATH, in order
path_bins() { type -ap "$1" 2>/dev/null; }
# find_bin NAME [PATH...] : NAME from $PATH, else the first executable PATH
find_bin() {
  local name=$1 b; shift
  { path_bins "$name"; printf '%s\n' "$@"; } | while IFS= read -r b; do
    [ -n "$b" ] && [ -x "$b" ] && { echo "$b"; break; }
  done
}
find_uv() { find_bin uv "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv" /opt/homebrew/bin/uv /usr/local/bin/uv; }

# run_to SECONDS CMD... : run CMD, killing it after SECONDS (macOS has no `timeout`)
run_to() {
  local secs=$1 pid wpid rc; shift
  "$@" &
  pid=$!
  ( sleep "$secs"; kill -9 "$pid" ) >/dev/null 2>&1 &
  wpid=$!
  wait "$pid" 2>/dev/null; rc=$?
  kill "$wpid" >/dev/null 2>&1; wait "$wpid" 2>/dev/null
  return "$rc"
}

# resolve PATH : follow symlinks (older macOS has no `realpath`/`readlink -f`)
resolve() {
  local f="$1" d n=0
  while [ -L "$f" ] && [ "$n" -lt 40 ]; do
    d=$(dirname "$f"); f=$(readlink "$f")
    case "$f" in /*) ;; *) f="$d/$f" ;; esac
    n=$((n + 1))
  done
  d=$(cd -P "$(dirname "$f")" 2>/dev/null && pwd -P) || d=$(dirname "$f")
  echo "$d/$(basename "$f")"
}

# uniq_bins < paths (one per line) : the existing executables, unique by
# resolved path, without version-manager shims
uniq_bins() {
  local b r seen=""
  while IFS= read -r b; do
    [ -n "$b" ] && [ -x "$b" ] && [ ! -d "$b" ] || continue
    case "$b" in */shims/*|*/.volta/bin/*) continue ;; esac
    r=$(resolve "$b")
    case "$seen" in *"<$r>"*) continue ;; esac
    seen="$seen<$r>"
    echo "$b"
  done
}

# brew_formula_of PATH : the Homebrew formula that owns PATH, or nothing
brew_formula_of() {
  local r; r=$(resolve "$1")
  case "$r" in */Cellar/*) cellar_formula "$r" ;; esac
}
# cellar_formula PATH : "name" from ".../Cellar/name/version/..."
cellar_formula() { echo "$1" | sed -E 's#.*/Cellar/([^/]+)/.*#\1#'; }

# python_xy PYTHON : "3.12"
python_xy() { "$1" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null </dev/null; }
# python_pip_dir PYTHON : the folder of the pip package this Python imports
python_pip_dir() {
  "$1" -c 'import os, pip; print(os.path.dirname(os.path.realpath(pip.__file__)))' 2>/dev/null </dev/null
}

# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------
# ver_ge A B : true if version A >= B (numeric fields, any separators)
ver_ge() {
  awk -v a="$1" -v b="$2" 'BEGIN {
    gsub(/^[^0-9]+/, "", a); gsub(/^[^0-9]+/, "", b)
    na = split(a, x, /[^0-9]+/); nb = split(b, y, /[^0-9]+/); n = (na > nb) ? na : nb
    for (i = 1; i <= n; i++) { p = x[i] + 0; q = y[i] + 0; if (p > q) exit 0; if (p < q) exit 1 }
    exit 0 }'
}
# major VERSION : "22" for "22.1.0"
major() { echo "$1" | sed 's/^[^0-9]*//' | awk -F'[^0-9]' '{print $1+0}'; }
# fixed_for_major VERSION "LIST" : the patched release of the same major, if any
fixed_for_major() {
  local m f; m=$(major "$1")
  for f in $2; do [ "$(major "$f")" = "$m" ] && { echo "$f"; return 0; }; done
  return 1
}
# max_major "LIST"
max_major() { local f m=0; for f in $1; do [ "$(major "$f")" -gt "$m" ] && m=$(major "$f"); done; echo "$m"; }

# patched_status VERSION "LIST" : PASS, or FAIL:<needed version>. The same
# major must be >= its fix; majors newer than the newest fixed line are fine;
# other lines have no fix at all.
patched_status() {
  local v="$1" list="$2" f
  if f=$(fixed_for_major "$v" "$list"); then
    if ver_ge "$v" "$f"; then echo PASS; else echo "FAIL:$f"; fi
  elif [ "$(major "$v")" -gt "$(max_major "$list")" ]; then
    echo PASS
  else
    echo "FAIL:$(echo "$list" | tr ' ' '/')"
  fi
}

# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------
# bundle_roots FILE : the affected roots a PEM bundle contains ("A, B"), or nothing
bundle_roots() {
  local f="$1" i found=""
  [ -r "$f" ] || return 1
  for i in 0 1 2; do
    if grep -qF "${ROOT_L1[$i]}" "$f" 2>/dev/null && grep -qF "${ROOT_L2[$i]}" "$f" 2>/dev/null; then
      found="${found:+$found, }${ROOT_NAMES[$i]}"
    fi
  done
  echo "$found"
}
cert_count() { local n; n=$(grep -c 'BEGIN CERTIFICATE' "$1" 2>/dev/null); echo "${n:-0}"; }
# is_bad_sha256 FINGERPRINT : true if it is one of the 16 compromised certificates
is_bad_sha256() { printf '%s\n' "${BAD_SHA256[@]}" | grep -qix "$1"; }
# ===========================================================================
# Probe programs
# ===========================================================================
# Small read-only programs that open TLS connections to the hosts they are
# given and print one line per host: "HOST ACCEPT|REJECT|NET detail".
# They are embedded here so the script stays a single file for `curl | bash`.
# write_probes saves them into the temporary folder, which is deleted at exit.
write_probes() {
  # Python: default SSL context and certifi, per interpreter (step 5)
  cat > "$EMD_TMP/check_tls.py" <<'EMD_PROBE_EOF'
# check_tls.py - part of emudhra-check (read-only probe).
# For each host in $EMD_HOSTS, opens a TLS connection with Python's default SSL
# context and, if installed, with certifi's bundle. Prints a few "#key value"
# facts (certifi, cafile, OpenSSL, pip, PIP_CERT), then one line per test:
# "default|certifi HOST ACCEPT|REJECT|NET detail". Sends no data.
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
def probe(job):
    name, mk, h = job
    s = None
    try:
        ctx = mk()
        s = socket.create_connection((h, 443), timeout=10)
        t = ctx.wrap_socket(s, server_hostname=h)
        t.close()
        return "%s %s ACCEPT" % (name, h)
    except Exception as e:
        m = (type(e).__name__ + ": " + str(e)).replace("\n", " ")[:160]
        cert = (VE is not None and isinstance(e, VE)) or "CERTIFICATE_VERIFY_FAILED" in m \
            or "certificate verify failed" in m
        return "%s %s %s %s" % (name, h, "REJECT" if cert else "NET", m)
    finally:
        try:
            s and s.close()
        except Exception:
            pass
jobs = [(n, mk, h) for n, mk in ctxs for h in hosts]
try:
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=16) as ex:
        results = list(ex.map(probe, jobs))
except ImportError:
    results = [probe(j) for j in jobs]
for line in results:
    print(line)
EMD_PROBE_EOF

  # Node.js: its built-in root list (step 6)
  cat > "$EMD_TMP/check_tls.js" <<'EMD_PROBE_EOF'
// check_tls.js - part of emudhra-check (read-only probe).
// For each host in $EMD_HOSTS, opens a TLS connection with Node's built-in
// root list and prints "HOST ACCEPT|REJECT|NET detail". Sends no data.
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
EMD_PROBE_EOF

  # Java: the JDK's default trust store, run as a single-file program (step 7)
  cat > "$EMD_TMP/EmudhraCheck.java" <<'EMD_PROBE_EOF'
// EmudhraCheck.java - part of emudhra-check (read-only probe).
// For each host given as an argument, does a TLS handshake with the JDK's
// default trust store and prints "HOST ACCEPT|REJECT|NET detail". Sends no data.
// Run as a single-file program: java EmudhraCheck.java HOST...
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import javax.net.ssl.*;

public class EmudhraCheck {
    public static void main(String[] args) throws Exception {
        final SSLSocketFactory f = (SSLSocketFactory) SSLSocketFactory.getDefault();
        ExecutorService pool = Executors.newFixedThreadPool(16);
        List<Future<String>> res = new ArrayList<>();
        for (final String h : args) res.add(pool.submit(() -> probe(f, h)));
        for (Future<String> r : res) System.out.println(r.get());
        pool.shutdown();
    }

    static String probe(SSLSocketFactory f, String h) {
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
        return h + " " + (r.length() > 170 ? r.substring(0, 170) : r);
    }
}
EMD_PROBE_EOF

  # macOS trust store: one HTTPS request through Foundation, the API Safari
  # and native apps use (step 2). Run with osascript (JavaScript for Automation).
  cat > "$EMD_TMP/check_mac.js" <<'EMD_PROBE_EOF'
// check_mac.js - part of emudhra-check (read-only probe, JavaScript for Automation).
// Makes one HTTPS request to https://HOST/ through Foundation (NSURLConnection),
// i.e. the macOS trust store that Safari and native apps use, and prints
// ACCEPT or FAILED. Run: osascript -l JavaScript check_mac.js HOST
// Foundation classes only show up in JXA after importing Cocoa, and reading the
// NSError back through Ref() crashes osascript, so it gives no error details.
ObjC.import('Cocoa');
function run(argv) {
  var req = $.NSURLRequest.requestWithURLCachePolicyTimeoutInterval(
    $.NSURL.URLWithString('https://' + argv[0] + '/'), 1, 12);
  var d = $.NSURLConnection.sendSynchronousRequestReturningResponseError(req, null, null);
  return (d === undefined || d === null || d.isNil()) ? 'FAILED' : 'ACCEPT';
}
EMD_PROBE_EOF
}
# ===========================================================================
# Live TLS tests
# ===========================================================================
# A tester prints one line per host: "HOST ACCEPT|REJECT|NET detail"
#   ACCEPT = the TLS handshake succeeded: the client trusts the chain
#   REJECT = certificate verification error (what we want for the test hosts)
#   NET    = network or other error (inconclusive)

# classify_msg TEXT : REJECT, NET or OTHER for a curl/git style error message
classify_msg() {
  if echo "$1" | grep -qiE 'certificate|issuer|self.signed|verify failed|not trusted|untrusted|SSL peer|unable to get local'; then
    echo REJECT
  elif echo "$1" | grep -qiE 'resolve|connect to|connection refused|timed out|timeout|network is unreachable|proxy|reset by peer|no route'; then
    echo NET
  else
    echo OTHER
  fi
}

# t_curl_one CURL HOST
t_curl_one() {
  local err rc st
  err=$("$1" -sS -o /dev/null --connect-timeout 8 --max-time 15 "https://$2/" 2>&1 </dev/null); rc=$?
  case $rc in
    0) st=ACCEPT ;;
    60|77|83) st=REJECT ;;                  # certificate problems
    5|6|7|28) st=NET ;;                     # proxy, DNS, connect, timeout
    *) st=$(classify_msg "$err"); [ "$st" = OTHER ] && st=NET ;;
  esac
  echo "$2 $st rc=$rc $(echo "$err" | head -1 | cut -c1-160)"
}

# t_git_one GIT HOST : `git ls-remote` of a repository that does not exist
t_git_one() {
  local err rc st
  err=$(GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/usr/bin/true run_to 25 "$1" \
        -c http.lowSpeedLimit=1 -c http.lowSpeedTime=15 \
        ls-remote "https://$2/emudhra-check.git" 2>&1 </dev/null); rc=$?
  if [ "$rc" -eq 0 ]; then st=ACCEPT
  else
    st=$(classify_msg "$err")
    # Any HTTP-level answer (404, "not found", "not valid") means TLS succeeded.
    [ "$st" = OTHER ] && st=ACCEPT
  fi
  echo "$2 $st $(echo "$err" | grep -v '^$' | tail -1 | cut -c1-160)"
}

# t_reach_one CURL HOST : "HOST UP" if a TCP+TLS exchange happened (whatever
# the certificate verdict), else "HOST DOWN"
t_reach_one() {
  local c="$1" rc
  [ -x "$c" ] || c=curl
  "$c" -s -o /dev/null --connect-timeout 6 --max-time 10 "https://$2/" </dev/null >/dev/null 2>&1; rc=$?
  case $rc in 5|6|7|28|56) echo "$2 DOWN" ;; *) echo "$2 UP" ;; esac
}

# t_mac_one _ HOST : the macOS trust store, through check_mac.js
t_mac_one() {
  local out rc st
  out=$(run_to 20 /usr/bin/osascript -l JavaScript "$EMD_TMP/check_mac.js" "$2" 2>&1 </dev/null); rc=$?
  case "$rc:$out" in
    0:ACCEPT*) st=ACCEPT ;;
    0:FAILED*)
      # The request failed: REJECT if the server answers TLS at all (step 1 test), else NET
      case "$(t_reach_one /usr/bin/curl "$2")" in
        *" UP") st=REJECT; out="refused by the macOS trust store (server reachable)" ;;
        *) st=NET; out="host not reachable" ;;
      esac ;;
    *) st=NET; out="probe failed (osascript exit $rc): ${out##*check_mac.js: }" ;;
  esac
  echo "$2 $st $(echo "$out" | head -1 | cut -c1-160)"
}

# par_hosts TESTER BIN OUTFILE : run "TESTER BIN HOST" for all hosts in
# parallel; OUTFILE gets the lines in host order
par_hosts() {
  local fn=$1 bin=$2 outf=$3 h i=0 p pids=()
  for h in "${ALL_HOSTS[@]}"; do
    i=$((i + 1))
    "$fn" "$bin" "$h" > "$EMD_TMP/par.$i" 2>/dev/null &
    pids+=($!)
  done
  for p in "${pids[@]}"; do wait "$p" 2>/dev/null; done
  : > "$outf"
  i=0; for h in "${ALL_HOSTS[@]}"; do i=$((i + 1)); cat "$EMD_TMP/par.$i" >> "$outf" 2>/dev/null; done
}

# judge FILE [N] : sums up a tester's output (N test hosts, default all) into
#   J_STATUS     PASS (rejected all, normal site OK), FAIL (trusts one or more),
#                WARN (inconclusive)
#   J_DETAIL     one line for the report
#   J_ACC        the test hosts it accepted (short names: "dv-g3b-emudhra ...")
#   J_CTRL_FAIL  1 if the normal site failed too
judge() {
  local f="$1" n_test="${2:-$N_TEST}" h st rest acc=0 rej=0 net=0 acc_list="" first_net="" ctrl="" ctrl_d=""
  local total ctrl_txt
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
  J_ACC="${acc_list# }"
  total=$((acc + rej + net))
  J_CTRL_FAIL=0; [ -n "$ctrl" ] && [ "$ctrl" != ACCEPT ] && J_CTRL_FAIL=1
  if [ "$ctrl" = ACCEPT ]; then ctrl_txt="normal site $CONTROL_HOST OK"
  elif [ -n "$ctrl" ]; then ctrl_txt="normal site $CONTROL_HOST FAILED ($(echo "$ctrl_d" | cut -c1-90))"
  else ctrl_txt="normal site not tested"; fi
  if [ "$total" -eq 0 ]; then
    J_STATUS=WARN; J_DETAIL="no result (client did not run)"
  elif [ "$acc" -gt 0 ]; then
    J_STATUS=FAIL; J_DETAIL="TRUSTS $acc/$n_test compromised test chains:$acc_list"
    case "$acc_list" in
      *-noct-*) J_DETAIL="$J_DETAIL (accepts chains never logged to CT: can be attacked unnoticed)" ;;
    esac
  elif [ "$rej" -eq "$n_test" ]; then
    if [ "$ctrl" = ACCEPT ] || [ -z "$ctrl" ]; then
      J_STATUS=PASS; J_DETAIL="rejected $rej/$n_test test chains; $ctrl_txt"
    else
      J_STATUS=WARN; J_DETAIL="rejected $rej/$n_test test chains but $ctrl_txt"
    fi
  else
    J_STATUS=WARN; J_DETAIL="inconclusive: rejected $rej/$n_test, network errors $net/$n_test (first: $(echo "$first_net" | cut -c1-110))"
  fi
}

# ---------------------------------------------------------------------------
# Tools that fall back to the macOS trust store (Apple's curl/git/python3,
# Homebrew git through the system libcurl, pip >= 24.2 through truststore)
# trust whatever macOS trusts. Step 2 tests macOS itself; these two helpers
# then point those tools at the step 2 fix instead of a fix of their own.
# ---------------------------------------------------------------------------
# sys_covers : true if macOS itself trusts every chain the last judged client trusted
sys_covers() {
  local h
  [ -n "$SYS_ACC" ] && [ -n "$J_ACC" ] || return 1
  for h in $J_ACC; do case " $SYS_ACC " in *" $h "*) ;; *) return 1 ;; esac; done
}
# apple_fix "DEFAULT FIX" : the fix text for a tool that may use the macOS trust store
apple_fix() {
  if sys_covers; then
    echo "$SYS_FIX"
  elif [ "$SYS_TESTED" -eq 0 ] && [ "$CERTPEM_CLEAN" -eq 1 ]; then
    echo "/etc/ssl/cert.pem is already clean, so this trust most likely comes from the macOS trust store: install the pending macOS/Safari updates (System Settings > General > Software Update) and restart."
  elif [ -n "$SYS_ACC" ]; then
    echo "$1 The chains macOS itself still trusts (step 2) need the pending macOS update."
  else
    echo "$1"
  fi
}
# ===========================================================================
# Automatic fixes (--fix)
# ===========================================================================
# Every change this script can make to the Mac is one of the fix_* functions
# below. A check only *registers* a fix with add_fix. Nothing runs unless the
# script was started with --fix, and then only after the list was shown and
# the user answered "y" (or passed --yes). Each fix runs in a fresh bash with
# no stdin, as the user, or with sudo for the ones marked "needs sudo"; its
# output goes to the log. Optional fixes (add_optional_fix) are asked about
# one by one, and skipped with --yes unless --with-optional.

# ---------------------------------------------------------------------------
# The fixes
# ---------------------------------------------------------------------------

# fix_certpem CN : needs sudo. The advisory's workaround for /etc/ssl/cert.pem
# (used by Apple's curl, git, python3, perl, ruby, openssl): remove the root
# whose subject ends in /CN=CN ("emSign ECC Root CA - G3", or, optionally,
# "AAA Certificate Services"). Keeps the original as
# /etc/ssl/cert.pem.pre-emudhra (the first time only), and refuses to write a
# result with fewer than 50 certificates. macOS updates may restore the file
# (macOS 27.2 did).
# Undo: sudo cp -p /etc/ssl/cert.pem.pre-emudhra /etc/ssl/cert.pem
fix_certpem() {
  local f=/etc/ssl/cert.pem b=/etc/ssl/cert.pem.pre-emudhra rc=1
  [ -f "$b" ] || cp -p "$f" "$b" || return 1
  # filters the current file, so the two fixes can run one after the other
  awk -v m="/CN=$1" '/^(###|===) / { skip = 0 }
       /^=== / && substr($0, length($0) - length(m) + 1) == m { skip = 1 }
       !skip' "$f" > "$f.new" || return 1
  if [ "$(grep -c 'BEGIN CERTIFICATE' "$f.new")" -ge 50 ]; then
    cat "$f.new" > "$f"; rc=$?
  else
    echo "The result has fewer than 50 certificates: $f not changed."
  fi
  rm -f "$f.new"
  return "$rc"
}

# fix_keychain_never_trust HOST... : marks the compromised intermediate that
# each test host is issued by as "Never Trust" in your login keychain, so the
# macOS trust store (Safari, native apps, Apple's curl/git/python3) refuses it.
# Needed while Apple has not blocked it itself. Only certificates on the
# advisory's SHA-256 list are touched. macOS asks for your password once per
# certificate.
# Undo: Keychain Access > login > Certificates > the "EM ... CA - G3x" ones > Delete.
fix_keychain_never_trust() {
  local d kc h c fp cn seen="" n=0 rc=0
  d=$(mktemp -d) || return 1
  cd "$d" || return 1
  kc="$HOME/Library/Keychains/login.keychain-db"; [ -f "$kc" ] || kc="$HOME/Library/Keychains/login.keychain"
  # certificate 2 of the chain each host sends is the intermediate that issued it
  for h in "$@"; do
    /usr/bin/openssl s_client -connect "$h:443" -servername "$h" -showcerts </dev/null 2>/dev/null \
      | awk -v p="${h%%.*}" '/BEGIN CERTIFICATE/ { n++; f = p "-" n ".pem" } f && n == 2 { print > f } /END CERTIFICATE/ { f = "" }'
  done
  for c in *.pem; do
    [ -f "$c" ] || continue
    fp=$(/usr/bin/openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g')
    [ -n "$fp" ] || continue
    printf '%s\n' "${BAD_SHA256[@]}" | grep -qix "$fp" || continue      # not on the advisory's list
    case "$seen" in *"$fp"*) continue ;; esac
    seen="$seen $fp"
    cn=$(/usr/bin/openssl x509 -in "$c" -noout -subject 2>/dev/null | sed 's/.*CN *= *//')
    if /usr/bin/security add-trusted-cert -r deny -k "$kc" "$c"; then
      echo "Never Trust: $cn ($fp)"; n=$((n + 1))
    else
      echo "FAILED: $cn ($fp)"; rc=1
    fi
  done
  cd / && rm -rf "$d"
  [ "$n" -gt 0 ] || { echo "Could not download any compromised intermediate from the test hosts."; rc=1; }
  return "$rc"
}

# fix_pip_upgrade PYTHON SPEC [--break-system-packages] : pip install --upgrade
# SPEC (for example "certifi>=2026.10.19") for that Python. The extra flag is
# used only for packages you installed with pip into Homebrew's Python.
# Undo: PYTHON -m pip install "certifi==<old version>"
fix_pip_upgrade() {
  "$1" -m pip install --disable-pip-version-check --upgrade ${3:+"$3"} "$2"
}

# fix_uv_pip_upgrade UV PYTHON SPEC : the same for a uv virtualenv (no pip in it)
fix_uv_pip_upgrade() {
  "$1" pip install --python "$2" --upgrade "$3"
}

# fix_apple_pip_cert STDLIB_DIR : needs sudo. Makes Apple's built-in pip
# (/usr/bin/python3) use /etc/ssl/cert.pem, by setting PIP_CERT in the stdlib
# sitecustomize.py, as the advisory does. Unlike a per-user usercustomize.py,
# this also covers virtualenvs created from /usr/bin/python3. If the stdlib is
# inside Xcode.app, macOS may refuse ("Operation not permitted").
# Undo: sudo sed -i '' '/PIP_CERT/d' STDLIB_DIR/sitecustomize.py
fix_apple_pip_cert() {
  local f="$1/sitecustomize.py"
  [ -d "$1" ] || return 1
  grep -q PIP_CERT "$f" 2>/dev/null && return 0
  echo 'import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")' >> "$f" || return 1
  chmod 644 "$f"
}

# fix_pyorg_certificates COMMAND_FILE : runs "Install Certificates.command",
# which python.org's installer puts in /Applications/Python 3.x (installs certifi).
fix_pyorg_certificates() {
  /bin/sh "$1"
}

# fix_java_blocked_certs FILE : needs sudo when FILE is not writable. Adds the
# 16 SHA-256 fingerprints to a JDK's blocked.certs (blacklisted.certs before
# JDK 16), which makes that JDK refuse those certificates. Roots in cacerts are
# not touched. Keeps the original as FILE.pre-emudhra.
# Undo: cp -p FILE.pre-emudhra FILE
fix_java_blocked_certs() {
  local f="$1" h
  [ -f "$f.pre-emudhra" ] || cp -p "$f" "$f.pre-emudhra" || return 1
  for h in "${BAD_SHA256[@]}"; do
    grep -qi "$h" "$f" || echo "$h" >> "$f" || return 1
  done
}

# fix_self_update BIN ARGS... : a tool's own updater ("uv self update",
# "rustup self update", "deno upgrade", ...)
fix_self_update() {
  "$@"
}

# fix_brew_upgrade BREW FORMULA... : brew update, then brew upgrade each
# formula on its own (a disabled or failing formula does not stop the others).
# Never runs as root.
fix_brew_upgrade() {
  local bb=$1 f rc=0; shift
  export HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1 HOMEBREW_NO_AUTO_UPDATE=1
  "$bb" update
  for f in "$@"; do
    if "$bb" info --json=v2 "$f" 2>/dev/null | grep -q '"disabled": *true'; then
      echo "skipped $f: disabled in Homebrew, uninstall it if unused"
      continue
    fi
    echo "== brew upgrade $f"
    "$bb" upgrade "$f" || { echo "FAILED: brew upgrade $f"; rc=1; }
  done
  return "$rc"
}

# ---------------------------------------------------------------------------
# Registering fixes
# ---------------------------------------------------------------------------
FX_SEP=$'\037'      # separates the words of a registered fix (they may contain spaces)

# add_fix NEEDS_SUDO(0/1) "label" FIX_FUNCTION [ARGS...] : registered once
add_fix() {
  local sudo=$1 label=$2 key a i=0; shift 2
  key=""; for a in "$@"; do key="$key${key:+$FX_SEP}$a"; done
  while [ "$i" -lt "$FX_N" ]; do [ "${FX_ARGS[$i]}" = "$key" ] && return 0; i=$((i + 1)); done
  FX_SUDO+=("$sudo"); FX_LABEL+=("$label"); FX_ARGS+=("$key"); FX_OPT+=(0)
  FX_N=${#FX_ARGS[@]}
}

# add_optional_fix NEEDS_SUDO "label" FIX_FUNCTION [ARGS...] : like add_fix, but
# --fix asks about it on its own (it may have side effects)
add_optional_fix() {
  local n=$FX_N
  add_fix "$@"
  [ "$FX_N" -gt "$n" ] && FX_OPT[$((FX_N - 1))]=1
  return 0
}

# add_brew FORMULA : collected into one "brew upgrade" fix (register_brew_fix)
add_brew() {
  case " $BREW_FORMULAS " in *" $1 "*) ;; *) BREW_FORMULAS="$BREW_FORMULAS $1" ;; esac
}
register_brew_fix() {
  local formulas
  [ -n "$BREW_FORMULAS" ] && [ ${#BREW_PREFIXES[@]} -gt 0 ] || return 0
  read -r -a formulas <<< "$BREW_FORMULAS"
  add_fix 0 "Homebrew: brew update && brew upgrade$BREW_FORMULAS" \
    fix_brew_upgrade "${BREW_PREFIXES[0]}/bin/brew" "${formulas[@]}"
}

# py_pip_fix PYTHON SPEC [BUNDLE] : registers the right package upgrade for an
# interpreter that may be changed (not Apple's), once per real interpreter.
# BUNDLE is the certifi cacert.pem in question, if known.
py_pip_fix() {
  local py="$1" spec="$2" bundle="$3" r="" f venv="" key uvb pkg=pip sp rb
  # a virtualenv's python is a symlink to its base interpreter: key on the venv
  [ -f "$(dirname "$py")/../pyvenv.cfg" ] && venv=$(cd "$(dirname "$py")/.." && pwd -P)
  if [ -n "$venv" ]; then key="<venv:$venv|$spec>"; else r=$(resolve "$py"); key="<$r|$spec>"; fi
  case "$PYFIX_SEEN" in *"$key"*) return ;; esac
  # the patched pip needs Python >= 3.10: nothing to upgrade on older ones
  case "$spec" in pip\>*) ver_ge "$(python_xy "$py")" 3.10 || return ;; esac
  PYFIX_SEEN="$PYFIX_SEEN$key"

  if [ -n "$venv" ]; then                                  # a virtualenv may always be changed
    if ls -d "$venv"/lib/python*/site-packages/pip >/dev/null 2>&1; then
      add_fix 0 "Upgrade '$spec' in virtualenv $venv" fix_pip_upgrade "$py" "$spec"
    else                                                   # uv venvs have no pip
      case "$spec" in pip\>*) return ;; esac
      uvb=$(find_uv)
      [ -n "$uvb" ] && add_fix 0 "Upgrade '$spec' in virtualenv $venv (uv)" fix_uv_pip_upgrade "$uvb" "$py" "$spec"
    fi
    return
  fi

  f=$(brew_formula_of "$py")
  if [ -n "$f" ]; then                                     # Homebrew Python is "externally managed"
    case "$spec" in certifi*) pkg=certifi ;; esac
    if [ "$pkg" = certifi ] && [ -n "$bundle" ]; then
      sp=$(dirname "$(dirname "$bundle")")
    else
      sp=$(dirname "$(python_pip_dir "$py")")
    fi
    rb=$(resolve "${bundle:-/nonexistent}")
    case "$rb" in
      */Cellar/ca-certificates/*|*/etc/ca-certificates/*) add_brew ca-certificates; return ;;   # brew's certifi links to it
      */Cellar/*) add_brew "$(cellar_formula "$rb")"; return ;;
    esac
    if grep -qx brew "$sp/$pkg"-*.dist-info/INSTALLER 2>/dev/null; then
      # installed by a brew formula: pip refuses ("no RECORD file"), brew must do it
      if [ "$pkg" = certifi ]; then add_brew ca-certificates; add_brew certifi; else add_brew "$f"; fi
    else
      add_fix 0 "Upgrade '$spec' installed with pip into Homebrew $f" fix_pip_upgrade "$py" "$spec" --break-system-packages
    fi
    return
  fi

  case "$r" in /usr/bin/*|/Library/Developer/*|/Applications/Xcode*) return ;; esac   # Apple's: read-only
  add_fix 0 "Upgrade '$spec' for $py" fix_pip_upgrade "$py" "$spec"
}

# ---------------------------------------------------------------------------
# Running fixes
# ---------------------------------------------------------------------------
# fx_words INDEX : the registered fix as an array FX_WORDS (function, args...)
fx_words() { IFS=$FX_SEP read -r -a FX_WORDS <<< "${FX_ARGS[$1]}"; }
# fx_text INDEX : the registered fix as a readable command line (for the log)
fx_text() { fx_words "$1"; printf '%q ' "${FX_WORDS[@]}"; }

# fx_run INDEX OUTFILE : run one fix in a fresh bash that gets only the fix_*
# functions and the fingerprint list, with sudo if it needs it
fx_run() {
  local defs fn
  fx_words "$1"
  defs=$(declare -p BAD_SHA256
         for fn in $(declare -F | awk '$3 ~ /^fix_/ { print $3 }'); do declare -f "$fn"; done)
  if [ "${FX_SUDO[$1]}" = 1 ] && [ "$(id -u)" != 0 ]; then
    sudo /bin/bash -c "$defs; \"\$@\"" emudhra-fix "${FX_WORDS[@]}"
  else
    /bin/bash -c "$defs; \"\$@\"" emudhra-fix "${FX_WORDS[@]}"
  fi > "$2" 2>&1 </dev/null
}

# fx_progress STATUS "label" "time" : one progress line of the auto-fix
fx_progress() {
  local st=$1 lbl="$2" tm="$3" tag
  case $st in RUN) tag="...." ;; *) tag=$st ;; esac
  plain "  [$(ts)] [$tag] $lbl${tm:+  ($tm)}"
  [ "$PRETTY" -eq 1 ] || return 0
  # the "running" line is replaced in place by its result line
  [ "$st" = RUN ] || printf '\r\033[K'
  printf '  %s %s%-6s%s %s%s' "$(icon "$st")" "$(stcol "$st")" "$st" "$C_OFF" "$(tilde "$lbl")" "${tm:+  $C_SKIP$tm$C_OFF}"
  [ "$st" = RUN ] || printf '\n'
}

# offer_fixes : check mode: list the fixes --fix would apply
offer_fixes() {
  local i sfx w opt
  [ "$FX_N" -gt 0 ] || return 0
  plain ""
  plain "$FX_N fix(es) can be applied automatically. Run again with --fix to apply them (you will be asked first):"
  plain "  curl -fsSL $SCRIPT_URL | bash -s -- --fix"
  plain "  (or: bash emudhra-check.sh --fix)"
  scr ""
  scr "$(rule "AUTO-FIX AVAILABLE" "$FX_N fix(es)")"
  i=0
  while [ "$i" -lt "$FX_N" ]; do
    sfx=""; [ "${FX_SUDO[$i]}" = 1 ] && sfx=" [admin password]"
    opt=""; [ "${FX_OPT[$i]}" = 1 ] && opt="[optional] "
    plain "    - $opt${FX_LABEL[$i]}$sfx"
    w=$((TERM_W - 7 - ${#opt})); [ -n "$sfx" ] && w=$((w - 18))
    scr "   🔧 ${opt:+$C_WARN$opt$C_OFF}$(fitm "$(tilde "${FX_LABEL[$i]}")" $w)${sfx:+ ${C_WARN}🔑 admin password${C_OFF}}"
    i=$((i + 1))
  done
  scr ""
  scr "  Apply them (you will be asked first; optional fixes are asked about one by one):"
  scr "  ${C_BOLD}curl -fsSL $SCRIPT_URL | bash -s -- --fix${C_OFF}"
}

# apply_fixes : --fix: show the list, confirm, run each fix, ask for a re-check
apply_fixes() {
  local i ans need_sudo=0 sudo_ok=0 t0 t1 rc outf n_ok=0 n_bad=0 n_skip=0 pw opt l go=()
  plain ""
  plain "================================ AUTO-FIX ==============================="
  scr ""
  scr "$(rule "AUTO-FIX")"
  if [ "$FX_N" -eq 0 ]; then
    out "Nothing can be fixed automatically. Follow the 'What to do' list above."
    return 0
  fi

  out "The following $FX_N fix(es) will be applied:"
  i=0
  while [ "$i" -lt "$FX_N" ]; do
    pw=""; [ "${FX_SUDO[$i]}" = 1 ] && pw=1
    opt=""; [ "${FX_OPT[$i]}" = 1 ] && opt="[optional] "
    plain "  $((i + 1)). $opt${FX_LABEL[$i]}${pw:+ [admin password]}"
    scr "  ${C_BOLD}$(printf '%2d' $((i + 1))).${C_OFF} ${opt:+$C_WARN$opt$C_OFF}$(tilde "${FX_LABEL[$i]}")${pw:+ ${C_WARN}🔑 admin password${C_OFF}}"
    logonly "       runs: $(fx_text $i)"
    i=$((i + 1))
  done
  out "Not fixed automatically (do these by hand): macOS/Safari updates, Electron apps, Docker Desktop and images, Node installed with nvm/fnm/volta, settings that disable verification."

  if [ "$OPT_YES" -eq 0 ]; then
    if ! ( : </dev/tty ) 2>/dev/null; then
      out "${C_WARN}No terminal to ask for confirmation. Re-run with --fix --yes to apply without asking.${C_OFF}"
      return 0
    fi
    printf 'Apply these fixes now? [y/N] ' > /dev/tty
    read -r ans </dev/tty
    logonly "Apply these fixes now? [y/N] $ans"
    case "$ans" in y|Y|yes|YES) ;; *) out "No changes made."; return 0 ;; esac
  fi

  # optional fixes: asked one by one; with --yes only applied with --with-optional
  i=0
  while [ "$i" -lt "$FX_N" ]; do
    go[i]=1
    if [ "${FX_OPT[$i]}" = 1 ] && [ "$OPT_OPTIONAL" -eq 0 ]; then
      go[i]=0
      if [ "$OPT_YES" -eq 0 ]; then
        printf 'Also apply optional fix %d (%s)? [y/N] ' $((i + 1)) "${FX_LABEL[$i]}" > /dev/tty
        read -r ans </dev/tty
        logonly "Also apply optional fix $((i + 1))? [y/N] $ans"
        case "$ans" in y|Y|yes|YES) go[i]=1 ;; esac
      fi
    fi
    [ "${go[$i]}" = 1 ] && [ "${FX_SUDO[$i]}" = 1 ] && need_sudo=1
    i=$((i + 1))
  done

  if [ "$need_sudo" -eq 1 ]; then
    if [ "$(id -u)" = 0 ]; then sudo_ok=1
    else
      out "Some fixes need your Mac admin password (sudo):"
      # shellcheck disable=SC2024  # the password prompt goes to the terminal
      if sudo -v </dev/tty 2>/dev/tty; then sudo_ok=1; else out "${C_WARN}sudo was not granted: admin fixes will be skipped.${C_OFF}"; fi
    fi
  fi

  i=0
  while [ "$i" -lt "$FX_N" ]; do
    t0=$(now_ms); outf="$EMD_TMP/fix.$i"
    fx_words $i
    if [ "${go[$i]}" != 1 ]; then
      n_skip=$((n_skip + 1))
      fx_progress SKIP "${FX_LABEL[$i]} - optional, not chosen" ""
      i=$((i + 1)); continue
    fi
    if [ "${FX_SUDO[$i]}" = 1 ] && [ "$sudo_ok" -eq 0 ]; then
      n_skip=$((n_skip + 1))
      fx_progress SKIP "${FX_LABEL[$i]} - needs admin password" ""
      i=$((i + 1)); continue
    fi
    fx_progress RUN "${FX_LABEL[$i]}" ""
    if [ "${FX_WORDS[0]}" = fix_brew_upgrade ] && [ "$(id -u)" = 0 ]; then
      echo "Homebrew must not run as root; run this script as your normal user." > "$outf"; rc=1
    else
      fx_run $i "$outf"; rc=$?
    fi
    t1=$(now_ms)
    sed 's/^/       | /' "$outf" >> "$LOG"
    if [ "$rc" -eq 0 ]; then
      n_ok=$((n_ok + 1))
      fx_progress DONE "${FX_LABEL[$i]}" "$(fmt_secs $((t1 - t0)))"
    else
      n_bad=$((n_bad + 1))
      fx_progress FAILED "${FX_LABEL[$i]} (exit $rc)" "$(fmt_secs $((t1 - t0)))"
      tail -3 "$outf" | while IFS= read -r l; do out "           ${C_SKIP}| $l${C_OFF}"; done
      if grep -q 'Operation not permitted' "$outf"; then
        out "           ${C_WARN}macOS blocked this change (files inside an app or a protected folder). Do it by hand, or allow Terminal in System Settings > Privacy & Security > App Management, then run --fix again.${C_OFF}"
      fi
    fi
    i=$((i + 1))
  done
  plain "Auto-fix finished: $n_ok done, $n_bad failed, $n_skip skipped."
  scr "  Auto-fix finished: ${C_PASS}$n_ok done${C_OFF}, ${C_FAIL}$n_bad failed${C_OFF}, $n_skip skipped."
  EMD_RERUN=1
}
# ===========================================================================
# Step 1: can the live tests reach the test hosts?
# ===========================================================================
step_connectivity() {
  local h st reach=0 unreach="" proxy
  step "Connectivity to the advisory's test hosts" "Live checks need to reach the $N_TEST test hosts on port 443."
  par_hosts t_reach_one /usr/bin/curl "$EMD_TMP/reach"
  while read -r h st; do
    [ "$h" = "$CONTROL_HOST" ] && continue
    if [ "$st" = UP ]; then reach=$((reach + 1)); else unreach="$unreach ${h%%.*}"; fi
  done < "$EMD_TMP/reach"
  if [ "$reach" -eq "$N_TEST" ]; then
    record PASS "Test hosts reachable" "$reach/$N_TEST reachable on port 443"
  elif [ "$reach" -gt 0 ]; then
    record WARN "Test hosts reachable" "only $reach/$N_TEST reachable (not:$unreach); some live results will be inconclusive"
  else
    record WARN "Test hosts reachable" "none reachable; live results will be inconclusive (offline, firewall or proxy-only network)"
  fi

  check_start
  proxy="${HTTPS_PROXY:-${https_proxy:-${ALL_PROXY:-$all_proxy}}}"
  if [ -n "$proxy" ]; then
    record WARN "Proxy settings" "HTTPS proxy is set ($proxy); curl/git/pip go through it, Python/Node/Java socket tests do not. A TLS-inspecting proxy can hide or change results."
  else
    record PASS "Proxy settings" "no HTTPS proxy in environment"
  fi
  step_end
}
# ===========================================================================
# Step 2: macOS updates, Keychain, /etc/ssl/cert.pem, the macOS trust store
# ===========================================================================
step_macos() {
  step "macOS system trust" "Safari and native apps use the macOS trust store; Apple blocked the intermediates on 22 Oct 2026."
  check_software_updates
  check_start; check_keychain
  check_start; check_certpem
  check_start; check_macos_trust_store
  check_start; check_browsers
  step_end
}

# check_software_updates : the `softwareupdate -l` started in the background.
# Sets SWU_IMPORTANT and MAC_UPTODATE for the checks below.
check_software_updates() {
  local upd titles others
  if [ "$IS_MAC" -eq 0 ]; then record SKIP "macOS software updates" "not macOS"; return; fi
  if [ -z "$SWU_PID" ]; then record SKIP "macOS software updates" "skipped (--quick)"; return; fi
  wait "$SWU_PID" 2>/dev/null
  upd=$(cat "$EMD_TMP/swu.out" 2>/dev/null)
  titles=$(echo "$upd" | grep -E '^[[:space:]]*Title:' | sed -E 's/^[[:space:]]*Title: *([^,]*), *Version: *([^,]*).*/\1 \2/')
  [ -n "$titles" ] || titles=$(echo "$upd" | grep -E '^[[:space:]]*\* Label:' | sed -E 's/^[[:space:]]*\* Label: *//')
  SWU_IMPORTANT=$(echo "$titles" | grep -iE 'macOS|Safari|Security' | tr '\n' ';')
  others=$(echo "$titles" | grep -viE 'macOS|Safari|Security' | grep . | tr '\n' ';')
  if echo "$upd" | grep -qi 'No new software available'; then
    MAC_UPTODATE=1
    record PASS "macOS software updates" "$OS_NAME $OS_VER is up to date"
  elif [ -n "$SWU_IMPORTANT" ]; then
    record FAIL "macOS software updates" "updates available: $SWU_IMPORTANT${others:+ (also: $others)}" \
      "Install them: System Settings > General > Software Update, then restart.
macOS updates up to 27.2 do not fix Apple's curl/git/python3 and may undo the /etc/ssl/cert.pem fix: run this script again after updating."
  elif [ -n "$others" ]; then
    record INFO "macOS software updates" "macOS and Safari are up to date; other updates available: $others"
  else
    record WARN "macOS software updates" "could not get the update list ($(echo "$upd" | tail -1 | cut -c1-100))" \
      "Check manually: System Settings > General > Software Update."
  fi
}

# check_keychain : custom trust settings, and compromised certificates stored
# in the login/System keychains
check_keychain() {
  local cn hsh kc_hits="" trust_lines trusted denied
  if ! have security; then record SKIP "Keychain" "'security' tool not available (not macOS)"; return; fi
  for cn in "EM DV TLS CA - G3" "EM OV TLS CA - G3" "EM EV TLS CA - G3" "EM OV CS CA - G3"; do
    for hsh in $(security find-certificate -a -Z -c "$cn" 2>/dev/null </dev/null | awk '/SHA-256 hash:/ {print $3}'); do
      is_bad_sha256 "$hsh" && kc_hits="$kc_hits $cn($(echo "$hsh" | cut -c1-12))"
    done
  done
  # one "NAME|deny" or "NAME|allow" line per certificate with custom trust settings
  trust_lines=$( { security dump-trust-settings 2>/dev/null; security dump-trust-settings -d 2>/dev/null; } </dev/null \
    | awk '/^Cert [0-9]+:/ { if (n != "") print n "|" (d ? "deny" : "allow"); n = $0; sub(/^Cert [0-9]+: */, "", n); d = 0; next }
           /Result Type/ && /Deny/ { d = 1 }
           END { if (n != "") print n "|" (d ? "deny" : "allow") }' \
    | grep -E "^($BAD_CN_REGEX|emSign|AAA Certificate Services)")
  trusted=$(echo "$trust_lines" | grep '|allow$' | cut -d'|' -f1)
  denied=$(echo "$trust_lines" | grep '|deny$' | cut -d'|' -f1 | sort -u | tr '\n' ';')
  if [ -n "$trusted" ]; then
    record FAIL "Keychain custom trust" "custom trust settings exist for: $(echo "$trusted" | tr '\n' ';')" \
      "Open Keychain Access, find these certificates, open Trust and set 'Use System Defaults' (or delete them)."
  elif [ -n "$denied" ]; then
    record PASS "Keychain custom trust" "blocked by you (Never Trust): $denied"
  else
    record PASS "Keychain custom trust" "no user/admin trust overrides for eMudhra/emSign/AAA certificates"
  fi

  check_start
  if [ -n "$kc_hits" ] && [ -n "$denied" ]; then
    record PASS "Keychain contents" "compromised intermediates in your keychains are marked Never Trust:$kc_hits"
  elif [ -n "$kc_hits" ]; then
    record WARN "Keychain contents" "compromised intermediates stored in your keychains:$kc_hits" \
      "Not trusted by itself, but delete them in Keychain Access unless your IT team put them there."
  else
    record PASS "Keychain contents" "no compromised intermediates in login/System keychains"
  fi
}

# check_certpem : /etc/ssl/cert.pem, the bundle of Apple's OpenSSL/LibreSSL tools.
# The emSign roots are always removed by --fix; removing AAA Certificate Services
# (the Sectigo cross-signs) is optional, as on the advisory, because unaffected
# sites still chain to it.
check_certpem() {
  local roots st=FAIL
  if [ ! -f /etc/ssl/cert.pem ]; then record SKIP "/etc/ssl/cert.pem" "file not found"; return; fi
  roots=$(bundle_roots /etc/ssl/cert.pem)
  if [ -z "$roots" ]; then
    CERTPEM_CLEAN=1
    record PASS "/etc/ssl/cert.pem" "does not contain the affected roots ($(cert_count /etc/ssl/cert.pem) certificates)"
    return
  fi
  case "$roots" in *"emSign ECC Root CA - G3"*)
    add_fix 1 "Remove emSign ECC Root CA - G3 from /etc/ssl/cert.pem (advisory workaround, backup kept)" \
      fix_certpem "emSign ECC Root CA - G3" ;;
  esac
  case "$roots" in *"emSign Root TLS CA - G3"*)
    add_fix 1 "Remove emSign Root TLS CA - G3 from /etc/ssl/cert.pem (backup kept)" fix_certpem "emSign Root TLS CA - G3" ;;
  esac
  case "$roots" in *"AAA Certificate Services"*)
    add_optional_fix 1 "Remove AAA Certificate Services from /etc/ssl/cert.pem (blocks the Sectigo cross-signed chains; may break some unaffected sites)" \
      fix_certpem "AAA Certificate Services" ;;
  esac
  # only AAA left: the user chose to keep it (the aaa test chains still FAIL in steps 3-5)
  [ "$roots" = "AAA Certificate Services" ] && st=WARN
  record "$st" "/etc/ssl/cert.pem" "still contains: $roots. Used by Apple's built-in curl, git, python3, perl, ruby, openssl. macOS 27.2 does not fix this file and undoes the workaround." \
"Advisory workaround (needs admin password; repeat after every macOS update):
[ -e /etc/ssl/cert.pem.orig ] || sudo cp -p /etc/ssl/cert.pem /etc/ssl/cert.pem.orig
t=\$(mktemp) && awk -v s='=== /C=IN/OU=emSign PKI/O=eMudhra Technologies Limited/CN=emSign ECC Root CA - G3' '/^(===|###) /{skip=0} \$0==s{skip=1} !skip' /etc/ssl/cert.pem > \"\$t\" && [ -s \"\$t\" ] && sudo install -m 0644 -o root -g wheel \"\$t\" /etc/ssl/cert.pem; rm -f \"\$t\"
Optional, also blocks the Sectigo cross-signed chains but may break some unaffected sites: the same with
s='=== /C=GB/ST=Greater Manchester/L=Salford/O=Comodo CA Limited/CN=AAA Certificate Services'"
}

# check_macos_trust_store : live test through Foundation (check_mac.js).
# Sets SYS_TESTED, SYS_ACC and SYS_FIX for the tools that ask macOS (steps 3-5).
check_macos_trust_store() {
  local fix="" kcfix h kc_hosts=()
  if [ "$IS_MAC" -eq 0 ] || [ ! -x /usr/bin/osascript ]; then record SKIP "macOS trust store" "not macOS"; return; fi
  par_hosts t_mac_one "" "$EMD_TMP/res"
  judge "$EMD_TMP/res"
  if [ "$J_STATUS" = FAIL ]; then
    SYS_TESTED=1; SYS_ACC="$J_ACC"
    # Apple has not blocked every compromised intermediate yet (G3B on macOS
    # 27.0.1). The user can mark them "Never Trust" in the login keychain; only
    # the hosts macOS still trusts, since each certificate is a password prompt.
    for h in "${TEST_HOSTS[@]}"; do
      case " $J_ACC " in *" ${h%%.*} "*) kc_hosts+=("$h") ;; esac
    done
    add_fix 0 "Mark the compromised eMudhra intermediates macOS still trusts as Never Trust in your login keychain (macOS asks for your password once per certificate)" \
      fix_keychain_never_trust "${kc_hosts[@]}"
    kcfix="Run with --fix: it marks the compromised intermediates as 'Never Trust' in your login keychain (macOS asks for your password once per certificate, about 3 times). That fixes Safari, native apps and every tool that asks macOS."
    if [ -n "$SWU_IMPORTANT" ]; then
      fix="$kcfix Also install the pending updates (${SWU_IMPORTANT%;}) and restart."
    elif [ "$MAC_UPTODATE" -eq 1 ]; then
      J_DETAIL="$J_DETAIL (even though macOS $OS_VER is up to date)"
      fix="Apple has not blocked these chains in macOS $OS_VER yet. $kcfix"
    else
      fix="$kcfix Also check System Settings > General > Software Update."
    fi
    SYS_FIX="macOS itself still trusts these chains (see step 2 'macOS trust store') and this tool asks macOS. Nothing to change in the tool: the step 2 keychain fix (--fix) fixes it too."
  elif [ "$J_STATUS" = PASS ]; then
    SYS_TESTED=1
  fi
  record "$J_STATUS" "macOS trust store (Safari, native apps)" "$J_DETAIL" "$fix"
}

# check_browsers : installed browsers (informational; they block the chains themselves)
check_browsers() {
  local a v br=""
  for a in "/Applications/Safari.app" "/Applications/Google Chrome.app" "/Applications/Firefox.app" \
           "/Applications/Microsoft Edge.app" "/Applications/Brave Browser.app" "/Applications/Arc.app" \
           "/Applications/Opera.app" "/Applications/Vivaldi.app" "/Applications/Zen.app"; do
    [ -d "$a" ] || continue
    v=$(defaults read "$a/Contents/Info" CFBundleShortVersionString 2>/dev/null)
    br="$br $(basename "$a" .app) ${v:-?};"
  done
  if [ -n "$br" ] && echo "$SWU_IMPORTANT" | grep -qi safari; then
    record WARN "Browsers" "${br# } - a Safari update is waiting" "Install the Safari update (System Settings > General > Software Update), then restart Safari."
  elif [ -n "$br" ]; then
    record INFO "Browsers" "${br# } (blocked via CRLSets/OneCRL since 17 Oct, Apple since 22 Oct; just keep them updated and restart)"
  else
    record SKIP "Browsers" "none found in /Applications"
  fi
}
# ===========================================================================
# Step 3: curl
# ===========================================================================
step_curl() {
  local p b v fix found=0
  step "curl" "Each curl binary must reject all $N_TEST test chains."
  { echo /usr/bin/curl
    for p in "${BREW_PREFIXES[@]}"; do echo "$p/opt/curl/bin/curl"; done
    path_bins curl; } | uniq_bins > "$EMD_TMP/list"
  while IFS= read -r b; do
    found=1
    v=$("$b" --version 2>/dev/null </dev/null | head -1 | awk '{print $2, $NF}')
    par_hosts t_curl_one "$b" "$EMD_TMP/res"
    judge "$EMD_TMP/res"
    fix=""
    if [ "$J_STATUS" = FAIL ]; then
      case "$b" in
        /usr/bin/curl) fix=$(apple_fix "Apply the /etc/ssl/cert.pem fix from step 2 (macOS updates do not update that file).") ;;
        */homebrew/*|/usr/local/*)
          if sys_covers; then fix="$SYS_FIX"
          else fix="brew update && brew upgrade ca-certificates curl"; add_brew ca-certificates; add_brew curl; fi ;;
        *) fix="Update the CA bundle used by this curl (curl -V shows the build; see $ADVISORY)." ;;
      esac
    fi
    record "$J_STATUS" "curl $b ($v)" "$J_DETAIL" "$fix"
  done < "$EMD_TMP/list"
  [ "$found" -eq 0 ] && record SKIP "curl" "not found"
  step_end
}
# ===========================================================================
# Step 4: git
# ===========================================================================
step_git() {
  local p b v fix found=0
  step "git" "git over HTTPS must reject all $N_TEST test chains."
  { [ -n "$DEV_DIR" ] && [ -x "$DEV_DIR/usr/bin/git" ] && echo /usr/bin/git
    for p in "${BREW_PREFIXES[@]}"; do echo "$p/bin/git"; done
    path_bins git | grep -vx /usr/bin/git; } | uniq_bins > "$EMD_TMP/list"
  while IFS= read -r b; do
    found=1
    v=$("$b" --version 2>/dev/null </dev/null | awk '{print $3}')
    par_hosts t_git_one "$b" "$EMD_TMP/res"
    judge "$EMD_TMP/res"
    fix=""
    if [ "$J_STATUS" = FAIL ]; then
      case "$b" in
        /usr/bin/git) fix=$(apple_fix "Apply the /etc/ssl/cert.pem fix from step 2. Also check 'git config --global --get http.sslCAInfo'.") ;;
        */homebrew/*|/usr/local/*)
          # Homebrew git uses macOS's libcurl, which falls back to the macOS trust store
          if sys_covers; then fix="$SYS_FIX"
          else fix="brew update && brew upgrade ca-certificates git. Also check 'git config --global --get http.sslCAInfo'."; add_brew ca-certificates; add_brew git; fi ;;
        *) fix="Update the CA bundle this git uses ('git config --show-origin --get-regexp http.ssl')." ;;
      esac
    fi
    record "$J_STATUS" "git $b ($v)" "$J_DETAIL" "$fix"
  done < "$EMD_TMP/list"
  if [ "$found" -eq 0 ]; then
    if [ -z "$DEV_DIR" ]; then record SKIP "git" "not installed (no Xcode Command Line Tools, no Homebrew git)"
    else record SKIP "git" "not found"; fi
  fi
  step_end
}
# ===========================================================================
# Step 5: Python, certifi and pip, per interpreter
# ===========================================================================
step_python() {
  local py found=0
  step "Python, certifi and pip" "Tests Python's default SSL context, the certifi bundle (used by requests/httpx) and pip, per interpreter."
  python_candidates | uniq_bins > "$EMD_TMP/pylist"
  while IFS= read -r py; do
    found=1
    check_start
    check_python "$py"
  done < "$EMD_TMP/pylist"
  [ "$found" -eq 0 ] && record SKIP "Python" "no Python 3 found (Apple's python3 needs Command Line Tools)"
  step_end
}

# python_candidates : every python3 we know where to look for, one per line
python_candidates() {
  local p c
  [ -n "$DEV_DIR" ] && [ -x "$DEV_DIR/usr/bin/python3" ] && echo /usr/bin/python3
  for p in "${BREW_PREFIXES[@]}"; do
    echo "$p/bin/python3"
    for c in "$p"/opt/python@3*/bin/python3.*; do          # python3.12, not python3.12-config
      case "$c" in */python3.[0-9]|*/python3.[0-9][0-9]) [ -e "$c" ] && echo "$c" ;; esac
    done
    echo "$p/Caskroom/miniconda/base/bin/python3"; echo "$p/Caskroom/miniforge/base/bin/python3"
  done
  ls -d /Library/Frameworks/Python.framework/Versions/*/bin/python3 \
        "$HOME"/.pyenv/versions/*/bin/python3 "$HOME"/.local/share/uv/python/*/bin/python3 \
        "$HOME"/.local/share/mise/installs/python/*/bin/python3 "$HOME"/.asdf/installs/python/*/bin/python3 2>/dev/null
  for c in miniconda3 anaconda3 miniforge3 mambaforge opt/anaconda3 opt/miniconda3; do echo "$HOME/$c/bin/python3"; done
  path_bins python3 | grep -vx /usr/bin/python3
}

# check_python PYTHON : runs check_tls.py, then records three results
check_python() {
  local py="$1" pv out="$EMD_TMP/py.out" certifi_v certifi_p cafile osl pipv pipcert
  pv=$("$py" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null </dev/null)
  if [ -z "$pv" ]; then record WARN "python $py" "could not run it"; return; fi
  EMD_HOSTS="${ALL_HOSTS[*]}" run_to 300 "$py" "$EMD_TMP/check_tls.py" > "$out" 2>"$EMD_TMP/py.err" </dev/null
  certifi_v=$(awk '$1 == "#certifi" { print $2 }' "$out")
  certifi_p=$(awk '$1 == "#certifi" { print $3 }' "$out")
  cafile=$(grep '^#cafile ' "$out" | cut -d' ' -f2-)
  osl=$(grep '^#openssl ' "$out" | cut -d' ' -f2 | tr '_' ' ')
  pipv=$(awk '$1 == "#pip" { print $2 }' "$out")
  pipcert=$(grep '^#pipcert ' "$out" | cut -d' ' -f2-)
  logonly "              python $py: version $pv, $osl, default cafile=$cafile, certifi=$certifi_v $certifi_p, pip=$pipv"

  check_python_default "$py" "$pv" "$cafile"
  check_start
  check_python_certifi "$py" "$pv" "$certifi_v" "$certifi_p"
  check_start
  check_python_pip "$py" "$pv" "$pipv" "$pipcert"
}

# check_python_default PYTHON VERSION CAFILE : Python's default SSL context
# (urllib, http.client, aiohttp...)
check_python_default() {
  local py="$1" pv="$2" cafile="$3" fix="" pyr pyx="" pyorg_cmd=""
  grep '^default ' "$EMD_TMP/py.out" | cut -d' ' -f2- > "$EMD_TMP/res"
  judge "$EMD_TMP/res"
  if [ "$J_STATUS" = FAIL ]; then
    case "$cafile" in
      /etc/ssl/cert.pem|/private/etc/ssl/cert.pem) fix=$(apple_fix "This Python uses /etc/ssl/cert.pem: apply the fix from step 2.") ;;
      */homebrew/*|/usr/local/*) fix="brew update && brew upgrade ca-certificates"; add_brew ca-certificates ;;
      *) fix="Python uses $cafile; update that bundle (for python.org builds: upgrade certifi and run 'Install Certificates.command')." ;;
    esac
  fi
  pyr=$(resolve "$py")
  case "$pyr" in
    /Library/Frameworks/Python.framework/Versions/*)
      pyx=$(echo "$pyr" | sed -E 's#.*/Versions/([0-9]+\.[0-9]+)/.*#\1#')
      [ -f "/Applications/Python $pyx/Install Certificates.command" ] && pyorg_cmd="/Applications/Python $pyx/Install Certificates.command" ;;
  esac
  if [ "$J_STATUS" = WARN ] && [ "$J_CTRL_FAIL" = 1 ]; then
    fix="This Python cannot verify normal sites either. python.org builds: run 'Install Certificates.command' in /Applications/Python 3.x/."
    [ -n "$pyorg_cmd" ] && add_fix 0 "Install certifi certificates for python.org Python $pyx" fix_pyorg_certificates "$pyorg_cmd"
  fi
  record "$J_STATUS" "python $pv ($py) ssl default" "$J_DETAIL" "$fix"
}

# check_python_certifi PYTHON VERSION CERTIFI_VERSION CERTIFI_BUNDLE
check_python_certifi() {
  local py="$1" pv="$2" certifi_v="$3" certifi_p="$4" fix="" croots
  if [ "$certifi_v" = none ] || [ -z "$certifi_v" ]; then
    record SKIP "python $pv certifi" "certifi not installed for this interpreter"
    return
  fi
  grep '^certifi ' "$EMD_TMP/py.out" | cut -d' ' -f2- > "$EMD_TMP/res"
  judge "$EMD_TMP/res"
  croots=$(bundle_roots "$certifi_p")
  if [ "$J_STATUS" = FAIL ] || [ -n "$croots" ]; then
    fix="\"$py\" -m pip install --upgrade 'certifi>=$FIX_CERTIFI'   (Homebrew Python: brew upgrade python-certifi; also upgrade it in each virtualenv)"
    py_pip_fix "$py" "certifi>=$FIX_CERTIFI" "$certifi_p"
    if [ "$J_STATUS" != FAIL ]; then J_STATUS=FAIL; J_DETAIL="bundle still contains: $croots; $J_DETAIL"; fi
  elif ! ver_ge "$certifi_v" "$FIX_CERTIFI"; then
    J_DETAIL="$J_DETAIL; version older than $FIX_CERTIFI but its bundle has no affected roots"
  fi
  record "$J_STATUS" "python $pv certifi $certifi_v" "$J_DETAIL" "$fix"
}

# pip_probe PYTHON : a real `pip download` of a package that does not exist,
# against one test host per root path and the normal index, in parallel.
# Writes tester lines to $EMD_TMP/res.
pip_probe() {
  local py="$1" h hh k=0 pp pids=() po st
  for h in "${PIP_HOSTS[@]}" "$PIP_CONTROL_HOST"; do
    k=$((k + 1))
    PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 run_to 60 "$py" -m pip download --no-deps --no-cache-dir \
      --retries 0 --timeout 10 -d "$EMD_TMP/pipdl.$k" --index-url "https://$h/simple/" \
      emudhra-check-nonexistent-probe > "$EMD_TMP/pip.$k" 2>&1 </dev/null &
    pids+=($!)
  done
  for pp in "${pids[@]}"; do wait "$pp" 2>/dev/null; done
  : > "$EMD_TMP/res"
  k=0
  for h in "${PIP_HOSTS[@]}" "$PIP_CONTROL_HOST"; do
    k=$((k + 1)); po=$(cat "$EMD_TMP/pip.$k" 2>/dev/null)
    if echo "$po" | grep -qiE 'CERTIFICATE_VERIFY_FAILED|SSLCertVerificationError|confirming the ssl certificate|certificate verify failed|SSLError'; then st=REJECT
    elif echo "$po" | grep -qiE 'Could not find a version|No matching distribution'; then st=ACCEPT
    else st=NET; fi
    hh=$h; [ "$h" = "$PIP_CONTROL_HOST" ] && hh=$CONTROL_HOST
    echo "$hh $st $(echo "$po" | grep -iE 'error|warning' | head -1 | cut -c1-140)" >> "$EMD_TMP/res"
  done
}

# check_python_pip PYTHON VERSION PIP_VERSION PIP_CERT
check_python_pip() {
  local py="$1" pv="$2" pipv="$3" pipcert="$4" fix="" stdlib f
  if [ "$pipv" = none ] || [ -z "$pipv" ]; then
    record SKIP "python $pv pip" "pip not installed for this interpreter"
    return
  fi
  pip_probe "$py"
  judge "$EMD_TMP/res" ${#PIP_HOSTS[@]}
  J_DETAIL=${J_DETAIL/normal site $CONTROL_HOST/normal index $PIP_CONTROL_HOST}
  if [ "$J_STATUS" = FAIL ]; then
    if { sys_covers || [ "$SYS_TESTED" -eq 0 ]; } && ver_ge "$pipv" 24.2 && ver_ge "$pv" 3.10; then
      # pip >= 24.2 on Python >= 3.10 verifies through macOS (truststore)
      fix="$SYS_FIX"
    elif sys_covers && [ "${pipcert:--}" != - ]; then
      # with PIP_CERT=/etc/ssl/cert.pem, Apple's Python falls back to macOS too
      fix="$SYS_FIX"
    elif ver_ge "$pipv" "$FIX_PIP"; then
      fix="pip $pipv is already patched, so the trusted chains come from its certificate settings: check PIP_CERT, REQUESTS_CA_BUNDLE and 'pip config list' (cert=...)."
    elif [ "$py" != /usr/bin/python3 ] && ! ver_ge "$pv" 3.10; then
      f=$(brew_formula_of "$py")
      fix="Python $pv is end-of-life and the patched pip needs Python 3.10+. Remove it if unused${f:+ (brew uninstall $f)}, or run its pip with --cert /etc/ssl/cert.pem (after the step 2 fix)."
    elif [ "$py" = /usr/bin/python3 ]; then
      # As the advisory does: PIP_CERT in the stdlib sitecustomize.py, which also
      # covers virtualenvs created from /usr/bin/python3 (a per-user
      # usercustomize.py is not loaded inside virtualenvs). Inside Xcode.app,
      # macOS may refuse the change ("Operation not permitted").
      stdlib=$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' 2>/dev/null </dev/null)
      fix="Built-in pip, and pip in virtualenvs made from /usr/bin/python3, use their own old copy of the roots. After the step 2 fix, point them at /etc/ssl/cert.pem (advisory, needs admin password):
F=\"\$(/usr/bin/python3 -c 'import sysconfig; print(sysconfig.get_path(\"stdlib\"))')/sitecustomize.py\" && echo 'import os; os.environ.setdefault(\"PIP_CERT\", \"/etc/ssl/cert.pem\")' | sudo tee -a \"\$F\" > /dev/null && sudo chmod 644 \"\$F\""
      [ -n "$stdlib" ] && add_fix 1 "Make Apple's pip (and virtualenvs made from /usr/bin/python3) use the fixed /etc/ssl/cert.pem (stdlib sitecustomize.py)" fix_apple_pip_cert "$stdlib"
    else
      fix="\"$py\" -m pip install --upgrade 'pip>=$FIX_PIP'"
      [ -n "$(brew_formula_of "$py")" ] && fix="\"$py\" -m pip install --upgrade --break-system-packages 'pip>=$FIX_PIP'"
      [ -n "$SYS_ACC" ] && fix="$fix   (chains macOS itself still trusts, see step 2, need the pending macOS update)"
      py_pip_fix "$py" "pip>=$FIX_PIP"
    fi
  elif ! ver_ge "$pipv" "$FIX_PIP" && [ "$J_STATUS" = PASS ]; then
    J_DETAIL="$J_DETAIL (pip $pipv < $FIX_PIP but this setup already rejects)"
  fi
  record "$J_STATUS" "python $pv pip $pipv" "$J_DETAIL (tested 1 host per root)" "$fix"
}
# ===========================================================================
# Step 6: Node.js (ships its own root list)
# ===========================================================================
step_node() {
  local nb found=0
  step "Node.js" "Node ships its own root list. Patched: $FIX_NODE (newer majors are fine)."
  node_candidates | uniq_bins > "$EMD_TMP/list"
  while IFS= read -r nb; do
    found=1
    check_start
    check_node "$nb"
  done < "$EMD_TMP/list"
  [ "$found" -eq 0 ] && record SKIP "Node.js" "not installed"
  step_end
}

node_candidates() {
  local p
  for p in "${BREW_PREFIXES[@]}"; do echo "$p/bin/node"; ls -d "$p"/opt/node@*/bin/node 2>/dev/null; done
  ls -d "$HOME"/.nvm/versions/node/*/bin/node \
        "$HOME/Library/Application Support/fnm/node-versions"/*/installation/bin/node \
        "$HOME"/.local/share/fnm/node-versions/*/installation/bin/node "$HOME"/.fnm/node-versions/*/installation/bin/node \
        "$HOME"/.volta/tools/image/node/*/bin/node "$HOME"/.asdf/installs/nodejs/*/bin/node \
        "$HOME"/.local/share/mise/installs/node/*/bin/node 2>/dev/null
  echo /usr/local/bin/node
  path_bins node
}

# check_node NODE : live test with check_tls.js, and the version
check_node() {
  local nb="$1" nv ps nf fix=""
  nv=$("$nb" --version 2>/dev/null </dev/null | tr -d 'v')
  if [ -z "$nv" ]; then record SKIP "node $nb" "binary does not start (broken or unlinked install), not usable"; return; fi
  EMD_HOSTS="${ALL_HOSTS[*]}" run_to 60 "$nb" "$EMD_TMP/check_tls.js" > "$EMD_TMP/res" 2>/dev/null </dev/null
  judge "$EMD_TMP/res"
  ps=$(patched_status "$nv" "$FIX_NODE")
  [ "$ps" != PASS ] && J_DETAIL="$J_DETAIL; version $nv is not a patched release (need ${ps#FAIL:})"
  if [ "$J_STATUS" = FAIL ] || [ "$ps" != PASS ]; then
    nf=$(brew_formula_of "$nb"); [ -n "$nf" ] && add_brew "$nf"
  fi
  if [ "$J_STATUS" = FAIL ]; then
    fix="Upgrade Node to a patched release (${ps#FAIL:}; newer majors are fine). Temporary workaround: NODE_OPTIONS=--use-system-ca"
  elif [ "$ps" != PASS ] && [ "$J_STATUS" = PASS ]; then
    J_STATUS=WARN
    if [ -n "$NODE_OPTIONS$NODE_EXTRA_CA_CERTS" ]; then
      fix="Upgrade Node to ${ps#FAIL:} or newer. It may pass here only because of your current settings (NODE_OPTIONS='$NODE_OPTIONS' NODE_EXTRA_CA_CERTS='$NODE_EXTRA_CA_CERTS')."
    else
      fix="Upgrade Node to ${ps#FAIL:} or newer. It passes the live test, but Node $(major "$nv") is not on the advisory's patched list (odd/old release lines get no fix)."
    fi
  fi
  record "$J_STATUS" "node $nv ($nb)" "$J_DETAIL" "$fix"
}
# ===========================================================================
# Step 7: Java (each JDK/JRE has its own trust store and blocked.certs)
# ===========================================================================
step_java() {
  local jh
  step "Java" "Each JDK/JRE must reject all $N_TEST test chains. Patched: Java $FIX_JAVA (8.0.511 = 8u511)."
  java_homes > "$EMD_TMP/jh"
  while IFS= read -r jh; do
    check_start
    check_java "$jh"
  done < "$EMD_TMP/jh"
  [ -s "$EMD_TMP/jh" ] || record SKIP "Java" "no JDK/JRE installed"
  step_end
}

# java_homes : the Java homes that have bin/java, unique by real path
java_homes() {
  local jh r p seen=""
  {
    [ -x /usr/libexec/java_home ] && /usr/libexec/java_home -V 2>&1 </dev/null | grep -E '^ +[0-9]' | awk '{print $NF}'
    for jh in "$HOME"/.sdkman/candidates/java/*; do [ -e "$jh" ] && [ "${jh##*/}" != current ] && echo "$jh"; done
    ls -d "$HOME"/Library/Java/JavaVirtualMachines/*/Contents/Home 2>/dev/null
    ls -d "$HOME"/.asdf/installs/java/* "$HOME"/.local/share/mise/installs/java/* 2>/dev/null
    for p in "${BREW_PREFIXES[@]}"; do ls -d "$p"/opt/openjdk*/libexec/openjdk.jdk/Contents/Home 2>/dev/null; done
    ls -d /Applications/*.app/Contents/jbr/Contents/Home 2>/dev/null
    ls -d /Applications/*.app/Contents/jre/Contents/Home 2>/dev/null
    [ -n "$JAVA_HOME" ] && echo "$JAVA_HOME"
  } | while IFS= read -r jh; do
    [ -n "$jh" ] || continue
    [ -x "$jh/bin/java" ] || { [ -x "$jh/Contents/Home/bin/java" ] && jh="$jh/Contents/Home"; }
    [ -x "$jh/bin/java" ] || continue
    r=$(cd -P "$jh" 2>/dev/null && pwd -P)
    case "$seen" in *"<$r>"*) continue ;; esac
    seen="$seen<$r>"
    echo "$r"
  done
}

# check_java JAVA_HOME : live test with EmudhraCheck.java (Java 11+),
# else a static check of the version and of blocked.certs. Only Oracle JDK
# builds have a patched release; OpenJDK builds are still pending.
check_java() {
  local jh="$1" jout jv jvn bc="" f s nb=0 ps fix="" jf japp js oracle=0
  jout=$("$jh/bin/java" -version 2>&1 </dev/null)
  jv=$(echo "$jout" | grep -m1 ' version "' | sed -E 's/.*version "([^"]*)".*/\1/')
  [ -n "$jv" ] || jv="unknown"
  jvn=$(echo "$jv" | sed -E 's/^1\.8\.0_([0-9]+).*/8.0.\1/; s/^1\.([0-9]+).*/\1/')
  echo "$jout" | grep -q 'Java(TM)' && oracle=1
  # JDK 16+ call it blocked.certs; JDK 8-15 blacklisted.certs (same format)
  for f in "$jh/lib/security/blacklisted.certs" "$jh/jre/lib/security/blacklisted.certs" \
           "$jh/lib/security/blocked.certs" "$jh/jre/lib/security/blocked.certs"; do [ -f "$f" ] && bc="$f"; done
  if [ -n "$bc" ]; then for s in "${BAD_SHA256[@]}"; do grep -qi "$s" "$bc" && nb=$((nb + 1)); done; fi
  if [ "$oracle" -eq 1 ]; then ps=$(patched_status "$jvn" "$FIX_JAVA")
  else ps="FAIL:pending"; fi                    # no patched OpenJDK release yet
  : > "$EMD_TMP/res"
  if [ "$(major "$jvn")" -ge 11 ]; then
    run_to 120 "$jh/bin/java" "$EMD_TMP/EmudhraCheck.java" "${ALL_HOSTS[@]}" > "$EMD_TMP/res" 2>"$EMD_TMP/java.err" </dev/null
  fi
  if [ -s "$EMD_TMP/res" ]; then
    judge "$EMD_TMP/res"
  elif [ "$nb" -eq 16 ] || [ "$ps" = PASS ]; then
    # Java 8, or a runtime without the compiler (IDE runtimes): decide statically
    J_STATUS=PASS; J_DETAIL="static check (no live test possible): patched version or all fingerprints blocked"
  else
    J_STATUS=FAIL; J_DETAIL="static check (no live test possible): version $jv not patched"
    [ "$oracle" -eq 0 ] && J_DETAIL="static check (no live test possible): OpenJDK $jv, no patched OpenJDK release yet"
  fi
  J_DETAIL="$J_DETAIL; $(basename "${bc:-blocked.certs}") has $nb/16 fingerprints"

  if [ "$J_STATUS" = FAIL ]; then
    case "$jh" in
      /Applications/*.app/*)
        # A runtime bundled in an app (Android Studio, IntelliJ...): macOS blocks
        # edits inside apps, and they would break the app's signature.
        japp=$(echo "$jh" | sed -E 's#^/Applications/([^/]+)\.app/.*#\1#')
        fix="This Java runtime is bundled inside $japp. Update $japp (it ships its own Java); do not edit files inside the app."
        bc="" ;;
      *)
        if [ "$ps" = PASS ]; then
          fix="Version $jv is a patched release, but this JDK still trusts the test chains. Add the 16 SHA-256 fingerprints from impacted-intermediates.json to ${bc:-$jh/lib/security/blocked.certs}. Do not delete roots from cacerts."
        elif [ "$oracle" -eq 0 ]; then
          fix="No patched OpenJDK release yet (advisory: pending). Add the 16 SHA-256 fingerprints from impacted-intermediates.json to ${bc:-$jh/lib/security/blocked.certs} (--fix does it), or use a patched Oracle JDK. Do not delete roots from cacerts."
        else
          fix="Upgrade this JDK to a patched release (${ps#FAIL:}), or add the 16 SHA-256 fingerprints from impacted-intermediates.json to ${bc:-$jh/lib/security/blocked.certs}. Do not delete roots from cacerts."
        fi ;;
    esac
    # Homebrew can lag behind the patched release: upgrade, and also block the
    # fingerprints in the current keg (Cellar files are writable).
    jf=$(brew_formula_of "$jh/bin/java")
    if [ -n "$jf" ] && [ "$ps" != PASS ] && [ "$oracle" -eq 1 ]; then
      add_brew "$jf"
      fix="brew update && brew upgrade $jf (Homebrew may not have ${ps#FAIL:} yet). Also add the 16 SHA-256 fingerprints from impacted-intermediates.json to ${bc:-$jh/lib/security/blocked.certs}. Do not delete roots from cacerts."
    fi
    if [ -n "$bc" ]; then
      js=1; [ -w "$bc" ] && js=0
      add_fix "$js" "Block the 16 compromised certificates in $bc (backup kept)" fix_java_blocked_certs "$bc"
    fi
  elif [ "$ps" != PASS ] && [ "$J_STATUS" = PASS ]; then
    if [ "$oracle" -eq 0 ]; then J_DETAIL="$J_DETAIL; OpenJDK patch pending but this JDK already rejects"
    else J_DETAIL="$J_DETAIL; version $jv older than ${ps#FAIL:} but this JDK already rejects"; fi
  fi
  record "$J_STATUS" "java $jv ($jh)" "$J_DETAIL" "$fix"
}
# ===========================================================================
# Step 8: other tools with their own CA list (version checks)
# ===========================================================================
step_other_tools() {
  step "Other tools with built-in CA lists" "Version check against the advisory's 'Who has patched?' table. Not installed = SKIP."
  check_homebrew_ca
  vcheck "uv" "$FIX_UV" "$(find_uv)" "uv self update   (or: brew upgrade uv)" self update
  vcheck "pixi" "$FIX_PIXI" "$(find_bin pixi "$HOME/.pixi/bin/pixi")" "pixi self-update" self-update
  vcheck "rustup" "$FIX_RUSTUP" "$(find_bin rustup "$HOME/.cargo/bin/rustup")" "rustup self update" self update
  vcheck "deno" "$FIX_DENO" "$(find_bin deno "$HOME/.deno/bin/deno")" "deno upgrade" upgrade
  vcheck "mise" "$FIX_MISE" "$(find_bin mise "$HOME/.local/bin/mise")" "mise self-update   (or: brew upgrade mise)" self-update -y
  vcheck "Claude Code" "$FIX_CLAUDE" "$(find_bin claude "$HOME/.claude/local/claude" "$HOME/.local/bin/claude")" "claude update" update
  vcheck "bun" "$FIX_BUN" "$(find_bin bun "$HOME/.bun/bin/bun")" "bun upgrade   (or: brew upgrade bun)" upgrade
  vcheck "GitHub CLI" "$FIX_GH" "$(find_bin gh)" "brew upgrade gh   (or install the latest release from cli.github.com)"
  vcheck "Docker CLI" "$FIX_DOCKER" "$(find_bin docker)" "Update Docker Desktop (Docker menu > Check for Updates), or: brew upgrade docker"
  check_docker_versions
  check_start; check_go
  check_start; check_perl_mozilla_ca
  step_end
}

# vcheck NAME PATCHED_VERSION BIN "how to fix" [UPDATER ARGS...] : version
# check; registers the tool's own updater (or brew upgrade) as the fix
vcheck() {
  local name="$1" fixv="$2" bin="$3" howfix="$4" v bf; shift 4
  check_start
  if [ -z "$bin" ] || ! [ -x "$bin" ]; then record SKIP "$name" "not installed"; return; fi
  v=$(run_to 20 "$bin" --version 2>/dev/null </dev/null | head -1 | grep -oE '[0-9]+(\.[0-9]+)+' | head -1)
  if [ -z "$v" ]; then record WARN "$name ($bin)" "could not read version"; return; fi
  if ver_ge "$v" "$fixv"; then
    record PASS "$name $v ($bin)" "patched (>= $fixv)"
    return
  fi
  record FAIL "$name $v ($bin)" "older than patched $fixv" "$howfix"
  bf=$(brew_formula_of "$bin")
  if [ -n "$bf" ]; then add_brew "$bf"
  elif [ $# -gt 0 ]; then add_fix 0 "Update $name" fix_self_update "$bin" "$@"; fi
}

# check_homebrew_ca : the ca-certificates formula and the bundles Homebrew's
# OpenSSL builds read
check_homebrew_ca() {
  local p d f bca="" roots
  check_start
  for p in "${BREW_PREFIXES[@]}"; do
    for d in "$p/Cellar/ca-certificates"/*; do [ -d "$d" ] && bca="$(basename "$d")"; done
  done
  if [ ${#BREW_PREFIXES[@]} -eq 0 ]; then
    record SKIP "Homebrew ca-certificates" "Homebrew not installed"
  elif [ -z "$bca" ]; then
    record SKIP "Homebrew ca-certificates" "formula not installed"
  elif ver_ge "$bca" "$FIX_BREW_CA"; then
    record PASS "Homebrew ca-certificates $bca" "patched (>= $FIX_BREW_CA)"
  else
    record FAIL "Homebrew ca-certificates $bca" "older than patched $FIX_BREW_CA" "brew update && brew upgrade ca-certificates"
    add_brew ca-certificates
  fi
  for p in "${BREW_PREFIXES[@]}"; do
    for f in "$p/etc/ca-certificates/cert.pem" "$p/etc/openssl@3/cert.pem" "$p/etc/openssl@1.1/cert.pem" "$p/etc/openssl/cert.pem"; do
      [ -f "$f" ] || continue
      check_start
      roots=$(bundle_roots "$f")
      if [ -z "$roots" ]; then
        record PASS "Homebrew bundle $f" "affected roots not present"
      elif [ "$f" = "$p/etc/openssl/cert.pem" ]; then
        record WARN "Homebrew bundle $f" "still contains: $roots; leftover from the old Homebrew openssl (1.0), current OpenSSL uses etc/openssl@3" \
          "Delete $f if nothing uses it (old openssl 1.0 builds only)."
      else
        record FAIL "Homebrew bundle $f" "still contains: $roots" "brew update && brew upgrade ca-certificates && brew postinstall ca-certificates"
        add_brew ca-certificates
      fi
    done
  done
}

# check_docker_versions : the Docker Desktop app and, if Docker is running, the
# Docker Engine (inside Docker Desktop, updating the app updates the engine)
check_docker_versions() {
  local app=/Applications/Docker.app v ev
  check_start
  if [ ! -d "$app" ]; then
    record SKIP "Docker Desktop" "not installed"
  else
    v=$(defaults read "$app/Contents/Info" CFBundleShortVersionString 2>/dev/null)
    if [ -z "$v" ]; then
      record WARN "Docker Desktop" "could not read version" "Update Docker Desktop (Docker menu > Check for Updates)."
    elif ver_ge "$v" "$FIX_DOCKER_DESKTOP"; then
      record PASS "Docker Desktop $v" "patched (>= $FIX_DOCKER_DESKTOP)"
    else
      record FAIL "Docker Desktop $v" "older than patched $FIX_DOCKER_DESKTOP" "Update Docker Desktop (Docker menu > Check for Updates)."
    fi
  fi
  check_start
  if ! have docker; then
    record SKIP "Docker Engine" "docker not installed"
    return
  fi
  ev=$(run_to 15 docker version --format '{{.Server.Version}}' 2>/dev/null </dev/null)
  if [ -z "$ev" ]; then
    record SKIP "Docker Engine" "Docker is not running"
  elif ver_ge "$ev" "$FIX_DOCKER"; then
    record PASS "Docker Engine $ev" "patched (>= $FIX_DOCKER)"
  else
    record FAIL "Docker Engine $ev" "older than patched $FIX_DOCKER" "Update Docker Desktop (Docker menu > Check for Updates), or the engine on the Docker host."
  fi
}

check_go() {
  local gob gv ps; gob=$(find_bin go /usr/local/go/bin/go)
  if [ -z "$gob" ]; then record SKIP "go" "not installed"; return; fi
  gv=$("$gob" version 2>/dev/null </dev/null | awk '{print $3}' | sed 's/^go//')
  ps=$(patched_status "$gv" "$FIX_GO")
  if [ "$ps" = PASS ]; then
    record PASS "go $gv" "patched (>= $FIX_GO)"
  else
    record WARN "go $gv" "not a patched release (need ${ps#FAIL:}). Go programs on macOS use the system verifier, but binaries you build for Linux/Docker embed the old list." \
      "Upgrade Go and rebuild binaries/images you ship."
  fi
}

check_perl_mozilla_ca() {
  local p pb mv found=0
  { echo /usr/bin/perl; for p in "${BREW_PREFIXES[@]}"; do echo "$p/bin/perl"; done; } | uniq_bins > "$EMD_TMP/list"
  while IFS= read -r pb; do
    # shellcheck disable=SC2016  # a Perl variable
    mv=$("$pb" -MMozilla::CA -e 'print $Mozilla::CA::VERSION' 2>/dev/null </dev/null)
    [ -n "$mv" ] || continue
    found=1
    check_start
    if ver_ge "$mv" "$FIX_PERL_MOZCA"; then record PASS "Perl Mozilla::CA $mv ($pb)" "patched"
    else record FAIL "Perl Mozilla::CA $mv ($pb)" "older than $FIX_PERL_MOZCA" "cpan Mozilla::CA   (or update the package that installed it)"; fi
  done < "$EMD_TMP/list"
  [ "$found" -eq 0 ] && record SKIP "Perl Mozilla::CA" "not installed"
}
# ===========================================================================
# Step 9: Electron apps (they embed Node's root list)
# ===========================================================================
step_electron() {
  local app found=0
  step "Electron apps (Slack, VS Code, Discord, ...)" "Electron embeds Node's root list. Patched Electron: $FIX_ELECTRON (newer majors are fine)."
  for app in /Applications/*.app /Applications/*/*.app "$HOME"/Applications/*.app; do
    [ -d "$app/Contents/Frameworks/Electron Framework.framework" ] || continue
    found=1
    check_start
    check_electron_app "$app"
  done
  [ "$found" -eq 0 ] && record SKIP "Electron apps" "none found in /Applications"
  step_end
}

# check_electron_app APP : the Electron version inside the app bundle
check_electron_app() {
  local app="$1" fw="$1/Contents/Frameworks/Electron Framework.framework" an av ev="" pl ps
  an=$(basename "$app" .app)
  av=$(defaults read "$app/Contents/Info" CFBundleShortVersionString 2>/dev/null)
  for pl in "$fw/Resources/Info.plist" "$fw/Versions/A/Resources/Info.plist" "$fw/Versions/Current/Resources/Info.plist"; do
    [ -f "$pl" ] && ev=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$pl" 2>/dev/null) && [ -n "$ev" ] && break
  done
  if [ -z "$ev" ]; then
    record WARN "$an ${av}" "Electron app, could not read Electron version" "Update the app to its latest version."
    return
  fi
  ps=$(patched_status "$ev" "$FIX_ELECTRON")
  if [ "$ps" = PASS ]; then
    record PASS "$an $av" "Electron $ev is patched"
  else
    record FAIL "$an $av" "Electron $ev is not patched (need ${ps#FAIL:})" "Update $an (app menu > Check for Updates). If it is already the latest version, the vendor has not shipped a fix yet: check again later."
  fi
}
# ===========================================================================
# Step 10: settings that turn verification off or point to a custom CA bundle
# ===========================================================================
step_tls_settings() {
  step "TLS settings in your environment" "Checks variables/configs that turn off verification or point to a custom CA bundle."
  check_insecure_settings
  check_start; check_custom_bundles
  step_end
}

check_insecure_settings() {
  local bad="" pc
  [ "$NODE_TLS_REJECT_UNAUTHORIZED" = 0 ] && bad="$bad NODE_TLS_REJECT_UNAUTHORIZED=0;"
  [ "$PYTHONHTTPSVERIFY" = 0 ] && bad="$bad PYTHONHTTPSVERIFY=0;"
  [ -n "$GIT_SSL_NO_VERIFY" ] && bad="$bad GIT_SSL_NO_VERIFY;"
  [ -f "$HOME/.curlrc" ] && grep -qE '^[[:space:]]*(-k|--insecure|insecure)([[:space:]]|$)' "$HOME/.curlrc" && bad="$bad ~/.curlrc insecure;"
  [ -f "$HOME/.npmrc" ] && grep -qE '^[[:space:]]*strict-ssl[[:space:]]*=[[:space:]]*false' "$HOME/.npmrc" && bad="$bad ~/.npmrc strict-ssl=false;"
  [ -f "$HOME/.gitconfig" ] && grep -qiE '^[[:space:]]*sslverify[[:space:]]*=[[:space:]]*false' "$HOME/.gitconfig" && bad="$bad ~/.gitconfig http.sslVerify=false;"
  for pc in "$HOME/.config/pip/pip.conf" "$HOME/Library/Application Support/pip/pip.conf" "$HOME/.pip/pip.conf"; do
    [ -f "$pc" ] && grep -qiE '^[[:space:]]*trusted-host' "$pc" && bad="$bad $pc trusted-host;"
  done
  if [ -n "$bad" ]; then
    record FAIL "Certificate verification disabled" "$bad" "Remove these settings. Never disable certificate verification (advisory)."
  else
    record PASS "Certificate verification disabled" "no settings found that turn verification off"
  fi
}

# custom_bundle_settings : "SETTING=FILE" lines for every custom CA bundle setting
custom_bundle_settings() {
  local v val
  for v in SSL_CERT_FILE REQUESTS_CA_BUNDLE CURL_CA_BUNDLE NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO PIP_CERT; do
    val=${!v}
    [ -n "$val" ] && echo "$v=$val"
  done
  if [ -f "$HOME/.gitconfig" ]; then
    val=$(awk -F= 'tolower($1) ~ /sslcainfo/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' "$HOME/.gitconfig" | head -1)
    [ -n "$val" ] && echo "git http.sslCAInfo=$val"
  fi
  if [ -f "$HOME/.npmrc" ]; then
    val=$(awk -F= '$1 ~ /^[ \t]*cafile/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' "$HOME/.npmrc" | head -1)
    [ -n "$val" ] && echo "npm cafile=$val"
  fi
}

check_custom_bundles() {
  local kv f roots
  custom_bundle_settings > "$EMD_TMP/cfiles"
  if [ ! -s "$EMD_TMP/cfiles" ]; then
    record PASS "Custom CA bundle settings" "none set (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE, NODE_EXTRA_CA_CERTS, GIT_SSL_CAINFO, PIP_CERT, git sslCAInfo, npm cafile)"
    return
  fi
  while IFS= read -r kv; do
    check_start
    f="${kv#*=}"; f="${f/#\~/$HOME}"
    if [ ! -f "$f" ]; then record WARN "Custom CA bundle: $kv" "file not found"; continue; fi
    roots=$(bundle_roots "$f")
    if [ -n "$roots" ]; then
      record FAIL "Custom CA bundle: $kv" "contains: $roots" "Replace it with an updated bundle, or remove the setting. Do not use bundles copied before 20 Oct 2026."
    else
      record PASS "Custom CA bundle: $kv" "affected roots not present"
    fi
  done < "$EMD_TMP/cfiles"
}
# ===========================================================================
# Step 11: CA bundle files on disk (certifi in virtualenvs, vendored copies...)
# ===========================================================================

# scan_bundles : candidate PEM bundle files, found by name. Started in the
# background at the beginning of the run (start_background_jobs).
scan_bundles() {
  local d names prune_nm=(-name node_modules -prune -o)
  names=(\( -name cacert.pem -o -name cert.pem -o -name ca-bundle.crt -o -name ca-bundle.pem
         -o -name ca-certificates.crt -o -name cacerts.pem -o -name tls-ca-bundle.pem -o -name ca-root-nss.crt \))
  [ "$OPT_DEEP" -eq 1 ] && prune_nm=()
  {
    # the home folder, without Library, media folders, caches and .git folders
    run_to 240 find "$HOME" -xdev \( -path "$HOME/Library" -o -path "$HOME/.Trash" -o -path "$HOME/.cache" \
      -o -path "$HOME/Pictures" -o -path "$HOME/Movies" -o -path "$HOME/Music" -o -name .git \) -prune -o \
      "${prune_nm[@]}" -type f "${names[@]}" -print 2>/dev/null
    # where Python, Homebrew and conda keep their packages
    for d in "$HOME/Library/Python" "${BREW_PREFIXES[@]}" /Library/Frameworks/Python.framework /opt/local /opt/anaconda3 /opt/miniconda3; do
      [ -d "$d" ] && run_to 120 find "$d" \( -name .git -o -path "*/Homebrew/Library" \) -prune -o -type f "${names[@]}" -print 2>/dev/null
    done
  } </dev/null | sort -u
}

step_bundle_files() {
  local f roots n_total=0 n_bad=0 n_clean=0
  step "CA bundle files on disk" "Finds PEM bundles (certifi in virtualenvs, vendored copies...) that still contain the affected roots."
  if [ "$OPT_SCAN" -eq 0 ]; then
    record SKIP "CA bundle scan" "skipped (--quick/--no-scan)"
    step_end
    return
  fi
  out "    (the scan started in the background at the beginning; waiting for it to finish...)"
  wait "$SCAN_PID" 2>/dev/null
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ "$(cert_count "$f")" -ge 20 ] || continue          # ignore single certificates and test fixtures
    n_total=$((n_total + 1))
    roots=$(bundle_roots "$f")
    if [ -n "$roots" ]; then
      n_bad=$((n_bad + 1))
      check_start
      check_bundle_file "$f" "$roots"
    else
      n_clean=$((n_clean + 1))
      logonly "              clean bundle: $f"
    fi
  done < "$EMD_TMP/bundles"
  check_start
  if [ "$n_total" -eq 0 ]; then
    record PASS "CA bundle scan" "no PEM CA bundles found"
  elif [ "$n_bad" -eq 0 ]; then
    record PASS "CA bundle scan" "$n_total bundle(s) checked, none contain the affected roots (list in log)"
  else
    record INFO "CA bundle scan" "$n_total bundle(s) checked: $n_bad still contain affected roots (FAIL/WARN lines above), $n_clean clean"
  fi
  step_end
}

# check_bundle_file FILE ROOTS : one bundle that contains affected roots. It is
# a FAIL if something uses it; leftovers and unused copies are a WARN.
check_bundle_file() {
  local f="$1" roots="$2" st=FAIL note="" fx envp pyxy envpy="" c sp pipdir pipused="" pipown="" pkg
  # the Python environment this file belongs to, and its interpreter (same X.Y)
  envp=$(echo "$f" | sed -E 's#/lib/python[0-9.]+/site-packages/.*##')
  pyxy=$(echo "$f" | sed -nE 's#.*/lib/python([0-9]+\.[0-9]+)/site-packages/.*#\1#p')
  if [ -n "$pyxy" ]; then
    # keg-only/unlinked Homebrew pythons use <prefix>/lib/pythonX.Y but live in <prefix>/opt/python@X.Y
    for c in "$envp/bin/python$pyxy" "$envp/opt/python@$pyxy/bin/python$pyxy" "$envp/bin/python3" "$envp/bin/python"; do
      [ -z "$envpy" ] && [ -x "$c" ] || continue
      [ "$(python_xy "$c")" = "$pyxy" ] && envpy="$c"
    done
  fi
  sp=$(echo "$f" | sed -E 's#(/site-packages)/.*#\1#')

  # a vendored pip copy only matters if it is the pip that Python imports
  case "$f" in
    */pip/_vendor/*)
      pipdir=$(echo "$f" | sed -E 's#(.*/pip)/_vendor/.*#\1#')
      if [ -n "$envpy" ]; then
        pipused=$(python_pip_dir "$envpy")
        if [ -n "$pipused" ] && [ "$pipused" = "$(cd -P "$pipdir" 2>/dev/null && pwd -P)" ]; then pipown=yes; else pipown=no; fi
      elif [ -z "$pyxy" ]; then
        pipown=src
      fi ;;
  esac

  if [ "$pipown" = src ]; then
    st=WARN; note="; a copy inside pip's source/build tree, not an installed pip"
    fx="No Python loads this copy, so it is safe to ignore. It goes away when the package that ships it is upgraded or removed."
  elif [ "$pipown" = no ]; then
    st=WARN; note="; not the pip that Python $pyxy uses (${pipused:-it has no pip})"
    fx="Leftover pip copy. Delete $pipdir if nothing uses it."
  elif [ -n "$pyxy" ] && [ -z "$envpy" ]; then
    st=WARN
    if [ -f "$envp/pyvenv.cfg" ]; then
      note="; virtualenv whose Python $pyxy no longer runs"
      fx="Recreate this virtualenv ($envp), or delete it if unused."
    else
      note="; leftover: no Python $pyxy is installed there"
      fx="Leftover from a removed Python $pyxy. Delete $sp if nothing uses it."
    fi
  else
    case "$f" in
      */pip/_vendor/*)
        fx="This is pip's vendored copy: upgrade pip in that environment (pip >= $FIX_PIP)."
        ver_ge "$pyxy" 3.10 || fx="pip's vendored copy for Python $pyxy, which is end-of-life: the patched pip needs Python 3.10+. Remove that Python if unused."
        [ -n "$envpy" ] && py_pip_fix "$envpy" "pip>=$FIX_PIP" "$f" ;;
      */site-packages/certifi/*)
        if [ -d "$sp/pip" ]; then
          fx="\"${envpy:-$envp/bin/python}\" -m pip install --upgrade 'certifi>=$FIX_CERTIFI'   (delete the environment if unused)"
        elif [ -n "$(find_uv)" ]; then
          fx="uv pip install --python \"${envpy:-$envp/bin/python}\" --upgrade 'certifi>=$FIX_CERTIFI'   (no pip in this environment; delete it if unused)"
        else
          fx="This environment has no pip (probably made by uv, which is not installed now). Delete $envp if unused; otherwise install uv (brew install uv) and run: uv pip install --python \"${envpy:-$envp/bin/python}\" --upgrade 'certifi>=$FIX_CERTIFI'"
        fi
        [ -n "$envpy" ] && py_pip_fix "$envpy" "certifi>=$FIX_CERTIFI" "$f" ;;
      */botocore/cacert.pem)
        if [ -d "$sp/certifi" ]; then
          st=WARN; note="; botocore's fallback copy, not used while certifi is installed here"
          fx="Keep certifi up to date in this environment; upgrade botocore/boto3 when AWS ships a new bundle."
        else
          fx="botocore's own copy (AWS CLI / boto3). Update the AWS CLI (official installer or brew upgrade awscli), or pip install certifi into this environment so botocore uses it."
        fi ;;
      */etc/ca-certificates/cert.pem)
        fx="brew update && brew upgrade ca-certificates"; add_brew ca-certificates ;;
      */etc/openssl/cert.pem)
        st=WARN; note="; leftover from the old Homebrew openssl (1.0)"
        fx="Delete this file if nothing uses it (current Homebrew OpenSSL uses etc/openssl@3)." ;;
      */Cellar/*)
        pkg=$(cellar_formula "$f")
        fx="Part of Homebrew $pkg: brew upgrade $pkg (or brew uninstall $pkg if unused)." ;;
      */gems/aws-sdk-core-*/ca-bundle.crt)
        st=WARN; note="; used only when an app calls Aws.use_bundled_cert!"
        fx="Ruby gem aws-sdk-core: gem update aws-sdk-core (with the Ruby that owns this folder)." ;;
      */gems/*/gems/*)
        pkg=$(echo "$f" | sed -E 's#.*/gems/[^/]+/gems/([^/]+)-[0-9][^/]*/.*#\1#')
        fx="Ruby gem $pkg ships this file: gem update $pkg (with the Ruby that owns this folder)." ;;
      */node_modules/*)
        pkg=$(echo "$f" | sed -E 's#.*/node_modules/((@[^/]+/)?[^/]+)/.*#\1#')
        fx="npm package $pkg ships this file: update it in that project (npm update $pkg)." ;;
      */homebrew/*) fx="brew update && brew upgrade" ;;
      *) fx="Update the software that ships this file (or ignore if unused)." ;;
    esac
  fi
  record "$st" "Bundle $f" "contains: $roots$note" "$fx"
}
# ===========================================================================
# Step 12: local Docker images (they carry their own CA bundle)
# ===========================================================================
step_docker() {
  local iid iname n_img
  step "Docker images" "Containers carry their own CA bundle; updating the Mac does not update them."
  if [ "$OPT_DOCKER" -eq 0 ]; then
    record SKIP "Docker images" "skipped (--quick/--no-docker)"
  elif ! have docker; then
    record SKIP "Docker images" "docker not installed"
  elif ! run_to 15 docker info >/dev/null 2>&1 </dev/null; then
    record SKIP "Docker images" "Docker is installed but not running"
  else
    # up to 60 tagged images, each image ID once
    docker image ls --format '{{.ID}} {{.Repository}}:{{.Tag}}' 2>/dev/null </dev/null | grep -v '<none>' \
      | awk '!seen[$1]++' | head -60 > "$EMD_TMP/images"
    n_img=$(wc -l < "$EMD_TMP/images" | tr -d ' ')
    [ "$n_img" -eq 0 ] && record SKIP "Docker images" "no local images"
    while read -r iid iname; do
      [ -n "$iid" ] || continue
      check_start
      check_docker_image "$iid" "$iname"
    done < "$EMD_TMP/images"
  fi
  step_end
}

# check_docker_image ID NAME : creates a stopped container (never started),
# copies the image's system CA bundle out of it, then removes the container
check_docker_image() {
  local iid="$1" iname="$2" cid got="" p roots
  cid=$(run_to 30 docker create "$iid" /emudhra-check-noop 2>/dev/null </dev/null)
  if [ -z "$cid" ]; then record WARN "image $iname" "could not create a stopped container to inspect it"; return; fi
  for p in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem \
           /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/cert.pem; do
    if run_to 30 docker cp -L "$cid:$p" - 2>/dev/null </dev/null | tar -xOf - > "$EMD_TMP/img.pem" 2>/dev/null && [ -s "$EMD_TMP/img.pem" ]; then
      got="$p"; break
    fi
  done
  docker rm -f "$cid" >/dev/null 2>&1 </dev/null
  if [ -z "$got" ]; then
    record INFO "image $iname" "no system CA bundle in this image (ca-certificates not installed), so there is no OS trust store to fix; app-level bundles are not checked"
    return
  fi
  roots=$(bundle_roots "$EMD_TMP/img.pem")
  if [ -n "$roots" ]; then
    record FAIL "image $iname" "$got contains: $roots" "Rebuild on an updated base image (apt-get/apk/dnf upgrade ca-certificates), push and redeploy."
  else
    record PASS "image $iname" "$got does not contain the affected roots (OS bundle only; app-level bundles inside are not checked)"
  fi
}
# ===========================================================================
# Step 13: certificates served by your own domains (only with --domain)
# ===========================================================================
step_domains() {
  local d hp chain names
  step "Certificates served by your domains" "Only with --domain. Fails if a served chain uses an affected intermediate."
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
}
# ===========================================================================
# Header and summary
# ===========================================================================

print_header() {
  local mode mode_more=""
  T_START=$(now_ms)
  if [ "$OPT_FIX" -eq 1 ]; then
    mode="CHECK + FIX - checks first, then asks before applying automatic fixes, then re-checks."
  elif [ "$OPT_AFTER_FIX" -eq 1 ]; then
    mode="RE-CHECK after fixes (read-only)"
  else
    mode="CHECK ONLY (dry-run) - changes nothing on this Mac. Add --fix to apply automatic fixes."
  fi
  plain "eMudhra CA compromise - Mac exposure check v$SCRIPT_VERSION"
  plain "Advisory : $ADVISORY"
  plain "Started  : $(date '+%Y-%m-%d %H:%M:%S %Z')"
  plain "Machine  : $(hostname -s 2>/dev/null) | $OS_NAME $OS_VER ($OS_BUILD) | $(uname -m) | user $(id -un)"
  plain "Log file : $LOG"
  plain "Mode     : $mode"
  plain "Statuses : PASS = safe | FAIL = must fix | WARN = could not decide or needs attention | SKIP = not installed / not run | INFO = for reference"
  scr ""
  scr "  ${C_BOLD}🔍 eMudhra CA exposure check${C_OFF}  ${C_SKIP}v${SCRIPT_VERSION%% *} · $ADVISORY${C_OFF}"
  scr ""
  scr "  ${C_SKIP}Machine${C_OFF}  $(hostname -s 2>/dev/null) · $OS_NAME $OS_VER ($OS_BUILD) · $(uname -m) · $(id -un)"
  case "$mode" in *" - "*) mode_more="${C_SKIP} · ${mode#* - }${C_OFF}" ;; esac
  scr "  ${C_SKIP}Mode   ${C_OFF}  ${C_BOLD}${mode%% - *}${C_OFF}${mode_more}"
  scr "  ${C_SKIP}Log    ${C_OFF}  $(tilde "$LOG")"
  scr "  ${C_SKIP}Legend ${C_OFF}  ✅ PASS safe   ❌ FAIL must fix   🟡 WARN have a look   ⚪ SKIP not installed   🔵 INFO"
  if [ "$(id -u)" = 0 ]; then
    out "${C_WARN}Note: running as root. Run it as your normal user so it checks your own tools and settings.${C_OFF}"
  fi
  if [ "$IS_MAC" -eq 0 ]; then
    out "${C_WARN}Note: this is not macOS; macOS-specific checks will be skipped.${C_OFF}"
  fi
}

# print_summary : counts, the plain table (log), the pretty table (screen)
print_summary() {
  local i
  T_TOTAL=$(fmt_secs $(($(now_ms) - T_START)))
  N_PASS=0; N_FAIL=0; N_WARN=0; N_SKIP=0
  i=0
  while [ "$i" -lt $R_N ]; do
    case ${R_STATUS[$i]} in
      PASS) N_PASS=$((N_PASS + 1)) ;; FAIL) N_FAIL=$((N_FAIL + 1)) ;;
      WARN) N_WARN=$((N_WARN + 1)) ;; SKIP) N_SKIP=$((N_SKIP + 1)) ;;
    esac
    i=$((i + 1))
  done
  print_summary_plain
  [ "$PRETTY" -eq 1 ] && print_summary_pretty
  return 0
}

# print_summary_plain : one line per check, then what to do (log; also the
# terminal when not in pretty mode)
print_summary_plain() {
  local i st l
  plain ""
  plain "================================ SUMMARY ================================"
  plain "Finished : $(date '+%Y-%m-%d %H:%M:%S %Z') (total $T_TOTAL)"
  plain "Results  : $N_PASS PASS, $N_FAIL FAIL, $N_WARN WARN, $N_SKIP SKIP"
  plain ""
  plain "$(printf '%-4s %-6s %-5s %-8s %s' '#' 'STATUS' 'STEP' 'TIME' 'CHECK')"
  i=0
  while [ "$i" -lt $R_N ]; do
    plain "$(printf '%-4s %-6s %-5s %-8s %s' $((i + 1)) "${R_STATUS[$i]}" "${R_STEP[$i]}" "${R_SECS[$i]}" "${R_NAME[$i]}")"
    i=$((i + 1))
  done
  if [ "$N_FAIL" -gt 0 ] || [ "$N_WARN" -gt 0 ]; then
    plain ""
    plain "What to do:"
    i=0
    while [ "$i" -lt $R_N ]; do
      st=${R_STATUS[$i]}
      if { [ "$st" = FAIL ] || [ "$st" = WARN ]; } && [ -n "${R_FIX[$i]}" ]; then
        plain "  [$st] #$((i + 1)) ${R_NAME[$i]}"
        printf '%s\n' "${R_FIX[$i]}" | while IFS= read -r l; do plain "        $l"; done
      fi
      i=$((i + 1))
    done
    plain ""
    plain "After fixing, restart the affected apps/terminals and run this script again."
  fi
  plain ""
  if [ "$N_FAIL" -gt 0 ]; then
    plain "RESULT: NOT OK - $N_FAIL item(s) still trust the compromised eMudhra intermediates or need updates."
  elif [ "$N_WARN" -gt 0 ]; then
    plain "RESULT: OK - no FAIL found. Review the $N_WARN WARN item(s) above."
  else
    plain "RESULT: OK - no FAIL found."
  fi
}

# cnt N COLOR : right-aligned count, a dim dot for zero
cnt() {
  if [ "$1" -eq 0 ]; then printf '%s   ·%s' "$C_SKIP" "$C_OFF"; else printf '%s%4s%s' "$2" "$1" "$C_OFF"; fi
}

# print_summary_pretty : one row per step, then the fixes, grouped (screen)
print_summary_pretty() {
  local sn i a b c d
  scr ""
  scr "$(rule "SUMMARY" "total $T_TOTAL")"
  scr "$(printf '   %-40s  ✅  ❌  🟡  ⚪  %7s' 'Step' 'Time')"
  sn=1
  while [ "$sn" -le "$CUR_STEP_NO" ]; do
    a=0; b=0; c=0; d=0; i=0
    while [ "$i" -lt $R_N ]; do
      if [ "${R_STEP[$i]}" = $sn ]; then
        case ${R_STATUS[$i]} in PASS) a=$((a + 1)) ;; FAIL) b=$((b + 1)) ;; WARN) c=$((c + 1)) ;; SKIP) d=$((d + 1)) ;; esac
      fi
      i=$((i + 1))
    done
    scr "$(printf '   %2s %s %s%s%s%s  %s%7s%s' $sn "$(padr "$(fit "${STEP_TITLE[$sn]}" 37)" 37)" "$(cnt $a "$C_PASS")" "$(cnt $b "$C_FAIL")" "$(cnt $c "$C_WARN")" "$(cnt $d "$C_SKIP")" "$C_SKIP" "${STEP_SECS[$sn]}" "$C_OFF")"
    sn=$((sn + 1))
  done
  scr "   $(printf '%-40s' '')──────────────────"
  scr "$(printf '   %-40s%s%s%s%s  %s%7s%s' 'Total' "$(cnt "$N_PASS" "$C_PASS")" "$(cnt "$N_FAIL" "$C_FAIL")" "$(cnt "$N_WARN" "$C_WARN")" "$(cnt "$N_SKIP" "$C_SKIP")" "$C_BOLD" "$T_TOTAL" "$C_OFF")"

  if [ "$N_FAIL" -gt 0 ] || [ "$N_WARN" -gt 0 ]; then
    scr ""
    scr "$(rule "WHAT TO DO" "same fix = one line")"
    print_grouped_fixes
    scr "  ${C_SKIP}After fixing, restart the affected apps/terminals and run this script again.${C_OFF}"
  fi
  scr ""
  if [ "$N_FAIL" -gt 0 ]; then
    scr "  ❌ ${C_FAIL}RESULT: NOT OK${C_OFF}  $N_FAIL item(s) still trust the compromised eMudhra intermediates or need updates."
  elif [ "$N_WARN" -gt 0 ]; then
    scr "  ✅ ${C_PASS}${C_BOLD}RESULT: OK${C_OFF}  no FAIL found. Have a look at the $N_WARN WARN item(s)."
  else
    scr "  ✅ ${C_PASS}${C_BOLD}RESULT: OK${C_OFF}  no FAIL found."
  fi
}

# print_grouped_fixes : the fix texts, FAIL first, then WARN; checks that
# share the same fix text are listed under one numbered line
print_grouped_fixes() {
  local want i j k=0 names nn first l done_=()
  for want in FAIL WARN; do
    i=0
    while [ "$i" -lt $R_N ]; do
      if [ "${R_STATUS[$i]}" = $want ] && [ -n "${R_FIX[$i]}" ] && [ -z "${done_[$i]}" ]; then
        k=$((k + 1)); names=""; nn=0; j=$i
        while [ "$j" -lt $R_N ]; do
          if [ -z "${done_[$j]}" ] && [ "${R_STATUS[$j]}" = $want ] && [ "${R_FIX[$j]}" = "${R_FIX[$i]}" ]; then
            done_[j]=1; nn=$((nn + 1)); names="$names${names:+, }$(tilde "${R_NAME[$j]}")"
          fi
          j=$((j + 1))
        done
        first=1
        printf '%s\n' "${R_FIX[$i]}" | while IFS= read -r l; do
          if [ $first = 1 ]; then printf '  %s %s%2d.%s %s\n' "$(icon $want)" "$C_BOLD" $k "$C_OFF" "$l"; first=0
          else printf '         %s\n' "$l"; fi
        done
        if [ "$nn" -gt 1 ]; then
          scr "        ${C_SKIP}$(fit "$nn checks: $names" $((TERM_W - 9)))${C_OFF}"
        else
          scr "        ${C_SKIP}$(fit "$names" $((TERM_W - 9)))${C_OFF}"
        fi
      fi
      i=$((i + 1))
    done
  done
}

# ===========================================================================
# Main
# ===========================================================================
# The checks, in the order they run. Each one is a "step_*" function above.
STEPS=(step_connectivity step_macos step_curl step_git step_python step_node
       step_java step_other_tools step_electron step_tls_settings
       step_bundle_files step_docker step_domains)

# start_background_jobs : the two slow, independent jobs start right away and
# are collected by their steps (2 and 11)
start_background_jobs() {
  if [ "$IS_MAC" -eq 1 ] && [ "$OPT_QUICK" -eq 0 ] && [ -x /usr/sbin/softwareupdate ]; then
    run_to 150 /usr/sbin/softwareupdate -l > "$EMD_TMP/swu.out" 2>&1 </dev/null &
    SWU_PID=$!
  fi
  if [ "$OPT_SCAN" -eq 1 ]; then
    scan_bundles > "$EMD_TMP/bundles" 2>/dev/null </dev/null &
    SCAN_PID=$!
  fi
}

# main ARGS... : one full run. It runs twice after --fix (the second run is a
# read-only re-check), so all state is set up again in init_state.
main() {
  local s
  init_state
  parse_options "$@" || return 2
  if [ "$OPT_HELP" -eq 1 ]; then usage; return 0; fi
  init_output
  init_workdir || return 1
  detect_environment
  write_probes
  print_header
  start_background_jobs

  for s in "${STEPS[@]}"; do "$s"; done

  print_summary
  register_brew_fix
  if [ "$OPT_FIX" -eq 1 ]; then apply_fixes; else offer_fixes; fi

  plain "Full log (send this file if asked): $LOG"
  scr ""
  scr "  📄 Full log (send this file if asked): $(tilde "$LOG")"
  [ "$N_FAIL" -eq 0 ]
}

# Everything runs inside functions, so the script also works when piped into
# bash (curl ... | bash). stdin is /dev/null for all checks; questions are read
# from /dev/tty.
EMD_ORIG_ARGS=("$@")
EMD_RERUN=0
main "$@" </dev/null
rc=$?
if [ "$EMD_RERUN" = 1 ]; then
  # Run every check again, read-only, to verify the fixes.
  set --
  for a in "${EMD_ORIG_ARGS[@]}"; do
    case "$a" in --fix|--yes|-y) ;; *) set -- "$@" "$a" ;; esac
  done
  echo ""
  echo "Re-checking after the fixes..."
  main --after-fix "$@" </dev/null
  rc=$?
fi
exit $rc
