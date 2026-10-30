# emudhra-check

A one-command check that tells you whether your Mac still trusts the compromised **eMudhra** certificate authorities. It also tells you exactly what to update.

> **Background.** On 20 October 2026, the private keys of 8 eMudhra intermediate CA certificates were found to be compromised. Anyone holding those keys can impersonate any website to software that still trusts them. Browsers are already protected, but many other programs on a Mac keep their own copy of the trusted certificates: curl, git, Python, pip, Node.js, Java, Electron apps and Docker images. Those copies need their own updates. Full advisory: https://emudhra.we-have-a-problem.com/

---

## Quick start

1. Open **Terminal**: press `⌘ Space`, type `Terminal`, then press Enter.
2. Paste this line and press Enter:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/infraspecdev/emudhra-check/main/emudhra-check.sh | bash
   ```

3. Wait about 1 minute until you see `RESULT:`.
   - `RESULT: OK`: nothing to do.
   - `RESULT: NOT OK`: see step 4.
4. Fix what it found. You can do this in two ways:
   - **Automatic.** Run it again with `--fix`. The script shows the list of fixes it can apply and asks `Apply these fixes now? [y/N]`. It may also ask for your Mac password (admin). Then it applies the fixes and checks everything again:

     ```bash
     curl -fsSL https://raw.githubusercontent.com/infraspecdev/emudhra-check/main/emudhra-check.sh | bash -s -- --fix
     ```

   - **By hand.** Follow the **What to do** list at the end of the output. Each line says what to update and how.
5. A log file is saved on your **Desktop** (`emudhra-check-<computer>-<date>.log`, plus `...-after-fix.log` after `--fix`). Send it to IT if they ask for it.

Some items always need you: installing macOS/Safari updates, updating apps like Slack or VS Code, and rebuilding Docker images. Run the check again afterwards until you get `RESULT: OK`.

---

## Is it safe to run?

Yes. By default (check mode, a dry-run) the script is **read-only**.

- It does **not** change, install or delete anything. It does not ask for your password or need `sudo`.
- It does **not** need git, Xcode, Homebrew or Python. It only uses tools that ship with macOS, and it skips anything you do not have.
- It does **not** send your data anywhere. The only network traffic is TLS connections to the advisory's 14 test servers and to `github.com` / `pypi.org`, which are used to confirm that normal sites still work.
- The only files it writes are the log on your Desktop and a temporary folder with its small test programs, which is deleted when it ends.
- One exception, only if Docker is running: to read the CA file inside each local image, it creates a stopped container from the image (it never starts it) and removes it right away. Use `--no-docker` to skip this.

In check mode, fixes are only **suggested**. They are applied only when you run with `--fix` **and** answer `y`. See [Auto-fix mode](#auto-fix-mode---fix).

### Read it before running

Download it, read it, then run it:

```bash
curl -fsSL https://raw.githubusercontent.com/infraspecdev/emudhra-check/main/emudhra-check.sh -o emudhra-check.sh
less emudhra-check.sh            # read it
bash emudhra-check.sh            # run it
```

The script is one file, split into sections that each start with a `# ====` banner. The list of sections is at the top of the file. Where to look:

| Section | What is in it |
|---|---|
| The header at the top | What the script reads, connects to and changes, and the list of sections |
| "Advisory data" | The data from the advisory: test servers, root markers, the 16 fingerprints, patched versions |
| "Step 1" … "Step 13" | One function per step of the check |
| "Automatic fixes" | **Every change `--fix` can make**, one `fix_*` function each, with how to undo it |
| "Probe programs" | The 4 small programs (Python, Node.js, Java, macOS JavaScript) that open the test connections |

---

## How it decides

The advisory runs **14 test servers**. Each one presents a certificate signed by one of the compromised CAs:

```
dv-g3b-emudhra.we-have-a-problem.com      dv-g3b-aaa-emudhra.we-have-a-problem.com
ov-g3b-emudhra.we-have-a-problem.com      ov-g3b-aaa-emudhra.we-have-a-problem.com
ev-g3b-emudhra.we-have-a-problem.com      ev-g3b-aaa-emudhra.we-have-a-problem.com
dv-g3c-emudhra.we-have-a-problem.com      dv-g3c-aaa-emudhra.we-have-a-problem.com
ov-g3c-emudhra.we-have-a-problem.com      ov-g3c-aaa-emudhra.we-have-a-problem.com
ev-g3c-emudhra.we-have-a-problem.com      ev-g3c-aaa-emudhra.we-have-a-problem.com
dv-g3b-noct-emudhra.we-have-a-problem.com dv-g3b-aaa-noct-emudhra.we-have-a-problem.com
```

The two `noct` servers (added by the advisory on 22 October) use certificates that were never logged to Certificate Transparency (CT). Programs that enforce CT, such as browsers, reject them even if they still trust the compromised CAs. A program that connects to them trusts the compromised CAs **and** does not enforce CT, so it could be attacked without anyone noticing. The result line says so when that happens.

For each program it finds, the script really connects to all 14 servers:

- A **safe** program refuses every connection with a certificate error. It must also still connect to a normal site (`github.com`). This proves that the fix did not break normal HTTPS.
- A **vulnerable** program connects successfully to one or more test servers. That program would also accept a fake certificate made with the leaked keys.

For things that cannot be tested live, the script reads the version or the certificate file instead. That covers tool versions, Electron apps, CA files on disk and Docker images. It compares them with the advisory's "Who has patched?" table, or looks for the affected root certificates inside the file.

---

## What it checks

| Step | What | How it is checked | If it FAILs |
|---|---|---|---|
| 1 | **Connectivity** | Can this Mac reach the 14 test servers? Is a proxy configured? | Only a warning. Live results may be inconclusive on a blocked network. |
| 2 | **macOS** | Pending macOS updates (`softwareupdate -l`). A live test of the macOS trust store itself (what Safari and native apps use; Apple's curl/git/python3, Homebrew git and pip 24.2+ also fall back to it). Custom Keychain trust for eMudhra/emSign/AAA certificates. Whether `/etc/ssl/cert.pem` still contains the affected roots: Apple's built-in curl, git, python3, perl and ruby use that file, and macOS updates do not fix it (macOS 27.2 did not fix it either, and it undid the workaround on Macs where it had been applied). Browser versions are shown for reference. | Install updates and restart. If macOS itself still trusts the chains (Apple had not blocked the G3B intermediates even in macOS 27.0.1), `--fix` marks them Never Trust in your login keychain; tools that only fail because of macOS are pointed to that fix. Run the advisory's `/etc/ssl/cert.pem` fix, which is printed in full. Reset the Keychain trust. |
| 3 | **curl** | Every curl on the Mac (Apple's `/usr/bin/curl`, Homebrew curl, others in your PATH) connects to the 14 test servers. | `/etc/ssl/cert.pem` fix, or `brew upgrade ca-certificates curl` |
| 4 | **git** | `git ls-remote` over HTTPS against the 14 test servers, for each git. Skipped if git is not installed. | Same as curl. Check `http.sslCAInfo`. |
| 5 | **Python** | For each Python 3 (Apple, Homebrew, python.org, pyenv, uv, conda, mise, asdf): (a) the default `ssl` context, used by `urllib`; (b) **certifi**, used by `requests`/`httpx`, live test plus a check of its file; (c) **pip**, a real `pip download` attempt. | Upgrade `certifi` to 2026.10.19 or later and `pip` to 26.2.2 or later. For Apple's pip, the advisory's `PIP_CERT` fix is printed. |
| 6 | **Node.js** | Every Node install (Homebrew, nvm, fnm, volta, asdf, mise): live test plus version check. Patched: 22.23.4, 24.22.1, 26.12.1. | Upgrade Node. |
| 7 | **Java** | Every JDK (`/usr/libexec/java_home`, SDKMAN, Homebrew, IDE runtimes in /Applications): live test plus a check of `blocked.certs`. Patched: Oracle JDK 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1. There is no patched OpenJDK release yet, so OpenJDK builds are not treated as patched by their version. | Upgrade an Oracle JDK, or add the 16 fingerprints to `blocked.certs` (the only option for OpenJDK until it is patched). |
| 8 | **Other tools** | Versions of Homebrew `ca-certificates` (and its `cert.pem` files), uv, pixi, rustup, deno, mise, bun, GitHub CLI, Docker CLI, Docker Engine, Docker Desktop, Go, Claude Code and Perl Mozilla::CA. | The upgrade command is printed for each tool. |
| 9 | **Electron apps** | For every app in /Applications built on Electron (Slack, VS Code, Discord, Notion, Postman…): its Electron version. Patched: 42.11.16, 43.8.1, 44.9.1 or newer. | Update the app. If you already have the latest version, the vendor has not shipped a fix yet; check again later. |
| 10 | **TLS settings** | Settings that switch verification off (`NODE_TLS_REJECT_UNAUTHORIZED=0`, `PYTHONHTTPSVERIFY=0`, `GIT_SSL_NO_VERIFY`, `insecure` in `~/.curlrc`, `strict-ssl=false` in `~/.npmrc`, `sslVerify=false` in `~/.gitconfig`, pip `trusted-host`). Custom CA files set by `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `PIP_CERT`, git `http.sslCAInfo` or npm `cafile`. | Remove the setting, or replace the old CA file. For a CA file that still has the affected roots, `--fix` can also remove them (optional). |
| 11 | **CA files on disk** | Searches your home folder, Homebrew, python.org Python and conda for CA bundle files (`cacert.pem`, `cert.pem`, `ca-bundle.crt`…). Each file is checked for the affected roots. This finds old `certifi` copies in virtualenvs and vendored copies. It skips `~/Library`, caches and `node_modules` (add `--deep` to include `node_modules`). | Upgrade `certifi`/pip in that virtualenv, or delete the environment if it is unused. Files left over from a Python that is no longer installed are shown as WARN: delete them if nothing uses them. |
| 12 | **Docker images** | If Docker is running: the system CA bundle inside each local image is read without running the image. | Rebuild on an updated base image (`apt-get`/`apk`/`dnf upgrade ca-certificates`), then push and redeploy. Updating the Mac does not update containers. |
| 13 | **Your domains** | Only with `--domain`: downloads the certificate chain your servers send and checks that it does not use an affected eMudhra intermediate. | Replace the certificate. |

---

## Reading the output

Every check prints one line: an icon and the status, the item, the detail and how long the check took. A `↳` line follows with the fix when you need to act. On screen, long lines are shortened to fit the window; the log file always has the full text.

```
━━ 3/13  curl ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 10:42:05
   Each curl binary must reject all 14 test chains.
  ❌ FAIL  curl /usr/bin/curl (8.7.1 LibreSSL/3.3.6) · TRUSTS 7/14 compromised test chai…  1.9s
           ↳ Apply the /etc/ssl/cert.pem fix from step 2 (macOS updates do not update that file).
  ✅ PASS  curl /opt/homebrew/opt/curl/bin/curl (8.10.1 OpenSSL/3.4.0) · rejected 14/14 …  1.7s
   └ step done in 3.6s
```

*(Example output.)*

| Status | Meaning |
|---|---|
| ✅ `PASS` | Safe. |
| ❌ `FAIL` | **Must fix.** This program still trusts the compromised CAs, or it is a version without the fix. |
| 🟡 `WARN` | The script could not decide (for example, no network to the test servers), or something needs a look. Read the detail. |
| ⚪ `SKIP` | Not installed or not applicable. Nothing to do. |
| 🔵 `INFO` | For reference only. |

At the end you get:

- a **summary** with one row per step: how many checks are ✅ / ❌ / 🟡 / ⚪, and how long the step took;
- a **What to do** list with only what you need to act on. Checks that need the same fix share one line;
- `RESULT: OK` or `RESULT: NOT OK`;
- the list of fixes `--fix` can apply for you, and the path of the log file.

The log file is plain text with every check on its own line (`[PASS]`, `[FAIL]`…), the full detail and the result for each of the 14 test servers. Send it to IT if they ask. With `--no-color`, or when the output is not a terminal, the screen shows the same plain format as the log.

---

## Auto-fix mode (`--fix`)

```bash
curl -fsSL https://raw.githubusercontent.com/infraspecdev/emudhra-check/main/emudhra-check.sh | bash -s -- --fix
```

1. All checks run first, the same as in check mode.
2. The script lists every fix it can apply. Fixes that need your admin password are marked 🔑 `admin password`.
3. It asks `Apply these fixes now? [y/N]`. Nothing changes unless you answer `y`. Fixes marked `[optional]` have side effects, so it then asks about each of them separately (`Also apply optional fix N (...)? [y/N]`).
4. It applies each fix and prints ✅ `DONE`, ❌ `FAILED` or ⚪ `SKIP` with the time it took. The full command output goes to the log.
5. It runs **all checks again** and saves the result to `...-after-fix.log`, so you can see what is fixed now.

| Problem found | Automatic fix | Needs password |
|---|---|---|
| `/etc/ssl/cert.pem` still has `emSign ECC Root CA - G3` (Apple curl/git/python3) | The advisory's workaround: remove that root. The original is kept as `/etc/ssl/cert.pem.pre-emudhra`. | yes |
| `/etc/ssl/cert.pem` still has `AAA Certificate Services` | **Optional, asked separately.** Removes that root too, which also blocks the Sectigo cross-signed intermediates. As the advisory warns, this may break some unaffected sites that still chain to it. If you keep it, Apple's curl/git/python3 still trust the `aaa` test chains. | yes |
| The macOS trust store still trusts test chains (Safari, Apple curl/git/python3, Homebrew git, pip 24.2+) | Downloads the intermediates the test servers send and marks those whose SHA-256 is on the advisory's list as **Never Trust** in your login keychain. Undo: delete the `EM … CA - G3x` certificates in Keychain Access > login. | your login password (macOS dialog) |
| Apple's built-in pip trusts the test servers | The advisory's fix: sets `PIP_CERT=/etc/ssl/cert.pem` in the `sitecustomize.py` of Apple's Python. This also covers virtualenvs created from `/usr/bin/python3`. If macOS blocks that change (when that Python is inside Xcode.app), it sets `PIP_CERT` in your own `usercustomize.py` instead, which works for you but not inside virtualenvs. | yes |
| A custom CA file set by `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, git `http.sslCAInfo`… still has the affected roots | **Optional, asked separately.** Removes those root certificates from the file. The original is kept as `<file>.pre-emudhra`. Removing `AAA Certificate Services` may break some unaffected sites, as on the advisory. | if the file is not yours |
| Homebrew ca-certificates / curl / git / gh / docker / go / node / python / uv / mise out of date | `brew update`, then `brew upgrade` for each formula, run as you. A formula that fails, or that Homebrew has disabled (such as `python@3.8`), does not stop the others. | no |
| Old certifi or pip in a virtualenv, pyenv, conda or python.org Python | `python -m pip install --upgrade 'certifi>=2026.10.19'` / `'pip>=26.2.2'`. For a uv virtualenv without pip: `uv pip install`. For certifi installed with pip into Homebrew Python: the same with `--break-system-packages`. | no |
| python.org Python cannot verify any site | Runs its `Install Certificates.command` | no |
| Java trusts the test servers | Adds the 16 compromised fingerprints to the JDK's `blocked.certs` / `blacklisted.certs` (for a Homebrew JDK also `brew upgrade`). The original is kept as `*.pre-emudhra`. A Java runtime inside an app (Android Studio, IntelliJ…) is not changed: update the app. | if the JDK is system-wide |
| uv, pixi, rustup, deno, mise, bun, Claude Code out of date | Their own self-update command | no |
| Go installed from go.dev (`/usr/local/go`) is not a patched release (1.26.10 for 1.26.x, 1.27.3 for 1.27.x) | Downloads the patched official installer from go.dev, checks it against the SHA-256 go.dev publishes and checks that it is signed by Google, then installs it. Nothing is installed if either check fails. Rebuild the binaries and images you ship afterwards. | yes |

These are **not** fixed automatically. The script tells you what to do:

- macOS and Safari updates, because they need a restart;
- Electron apps (Slack, VS Code…) and Docker Desktop: update them from the app;
- Docker images: rebuild and redeploy;
- Node installed with nvm/fnm/volta: install the patched version with your version manager;
- settings that turn off certificate verification: remove them yourself.

To undo the `/etc/ssl/cert.pem` change: `sudo cp -p /etc/ssl/cert.pem.pre-emudhra /etc/ssl/cert.pem`. This brings back both roots; to keep only the emSign fix, run `--fix` again and answer `n` to the optional fix. To undo a Java or custom CA file change, copy the `.pre-emudhra` file back in the same way.

For MDM or scripts, `--fix --yes` applies the fixes without asking. Optional fixes are then skipped; add `--with-optional` to apply them too. It needs to run as the logged-in user. Fixes that need sudo are skipped if sudo is not available.

---

## Speed

Every live test runs in parallel: all 14 test servers at once for each program, and the pip checks at the same time. The two slow parts start in the background as soon as the script starts: the macOS update check (`softwareupdate -l`) and the disk scan. A typical run takes about 1 minute. Use `--quick` to skip the update check, the disk scan and Docker.

---

## Options

```bash
curl -fsSL https://raw.githubusercontent.com/infraspecdev/emudhra-check/main/emudhra-check.sh | bash -s -- --quick
```

| Option | What it does |
|---|---|
| *(none)* | Check only (dry-run). Changes nothing. |
| `--fix` | Check, then offer to apply the automatic fixes, then check again. |
| `--yes` | With `--fix`: do not ask for confirmation. Optional fixes are skipped. |
| `--with-optional` | With `--fix`: also apply the optional fixes without asking (removing `AAA Certificate Services` from `/etc/ssl/cert.pem`, and removing the affected roots from custom CA files). |
| `--quick` | Skip the slow parts: the macOS update check, the disk scan and Docker. |
| `--no-scan` | Skip step 11, the CA file scan. |
| `--no-docker` | Skip step 12, Docker. |
| `--deep` | Include `node_modules` folders in the disk scan (slower). |
| `--domain a.com,b.com` | Also check the certificates served by your domains (step 13). |
| `--log FILE` | Save the log to `FILE` instead of the Desktop. |
| `--no-color` | Plain output, without colors or icons. |
| `--help` | Show the help text. |

Exit code: `0` = no FAIL, `1` = at least one FAIL. You can use it in scripts or MDM.

---

## FAQ

**I updated macOS. Why does `/usr/bin/curl` still FAIL?**
Apple's built-in curl, git and python3 check certificates against the file `/etc/ssl/cert.pem`, and that file was not updated. The script prints the advisory's fix, which needs an admin password. macOS 27.2 (26 October) did not fix the file and put the old one back on Macs where the fix had been applied, so run the check again (with `--fix`) after each update until Apple ships a fix.

**Can I just turn off certificate checking?**
No. That makes things much worse. The advisory explicitly says not to disable verification.

**I use a VPN or a security agent (Cloudflare WARP, Zscaler, antivirus web shield…).**
Tools that inspect HTTPS traffic re-sign certificates, which can hide or change the result. If you get unexpected results, turn them off for the run and try again.

**It says WARN for almost everything and "network errors".**
Your network probably blocks the test servers (some office networks do), or you are offline. Run it again on another network, for example a phone hotspot.

**An app I use is FAIL but I already have the latest version.**
The vendor has not shipped an Electron update yet. Keep the app updated and run the check again later.

**Does it check my servers and Kubernetes workloads?**
No. Step 12 only checks Docker images on this Mac, and step 13 only checks the certificates your domains present. Servers and containers in production need their own update and redeploy.

---

## Development

Edit `emudhra-check.sh` directly. Before pushing, check that `shellcheck emudhra-check.sh` reports nothing and that it runs with the bash 3.2 that macOS ships (`/bin/bash emudhra-check.sh`). Keep the code compatible with bash 3.2: no associative arrays, no `mapfile`, no `${var,,}`.

---

## Data source

The test servers, root-certificate markers, the 16 compromised certificate fingerprints and the patched versions come from the advisory and its source repository:

- https://emudhra.we-have-a-problem.com/
- https://github.com/galadran/we-have-a-problem.com (`chains/`, `roots.json`, `impacted-intermediates.json`)

If the advisory's "Who has patched?" table changes, update the `FIX_*` values in the "Advisory data" section of `emudhra-check.sh`.
