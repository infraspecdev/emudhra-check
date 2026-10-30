# Steps

The commands for the two scripts, in the order you run them:

1. [`emudhra-check.sh`](#1-emudhra-checksh-check-the-whole-mac): checks every HTTPS client on the Mac and, with `--fix`, fixes what it can.
2. [`fix-certpem.sh`](#2-fix-certpemsh-etcsslcertpem-only): fixes only `/etc/ssl/cert.pem`, the part that needs root (`emudhra-check.sh --fix` runs it for you).

## Get the scripts

```bash
git clone https://github.com/infraspecdev/emudhra-check.git
cd emudhra-check
git pull                        # later: get the latest scripts
```

Run every command below from that folder. Without git, the `curl` lines below work from anywhere.

---

## 1. `emudhra-check.sh`: check the whole Mac

Always run it as your **normal user, never with `sudo`**: most of its fixes change files in your home folder, and Homebrew refuses to run as root. It asks for your admin password itself, only for the fixes that need it.

### 1.1 Run the check (changes nothing)

```bash
bash emudhra-check.sh
```

Without git:

```bash
curl -fsSL https://raw.githubusercontent.com/infraspecdev/emudhra-check/main/emudhra-check.sh | bash
```

It takes about 1 minute and ends with `RESULT: OK` (nothing to do) or `RESULT: NOT OK`. The log is saved on your Desktop (`emudhra-check-<computer>-<date>.log`).

### 1.2 Read the result

| Status | Meaning |
|---|---|
| `PASS` | Safe. |
| `FAIL` | Must fix: it still trusts the compromised CAs, or is a version without the fix. |
| `WARN` | Could not decide, or needs a look: read the detail. |
| `SKIP` / `INFO` | Not installed, or for reference only. |

The **What to do** list at the end says what to update for each `FAIL`, and which fixes `--fix` can apply for you.

### 1.3 Fix automatically

```bash
bash emudhra-check.sh --fix
```

Without git:

```bash
curl -fsSL https://raw.githubusercontent.com/infraspecdev/emudhra-check/main/emudhra-check.sh | bash -s -- --fix
```

1. It runs all checks, then lists the fixes it can apply. Fixes marked `admin password` need your Mac password.
2. It asks `Apply these fixes now? [y/N]`. Nothing changes unless you answer `y`.
3. Fixes marked `[optional]` (for example removing `AAA Certificate Services`) are asked about one by one.
4. It applies them, shows `DONE` / `FAILED` / `SKIP` for each, checks everything again and saves `...-after-fix.log` on the Desktop.

### 1.4 Fix the rest by hand

`--fix` cannot do these; the What to do list says how:

- macOS and Safari updates: System Settings > General > Software Update, then restart. Then check `/etc/ssl/cert.pem` again ([step 2.3](#23-after-every-macos-update)).
- Electron apps (Slack, VS Code, Postman…) and Docker Desktop: update them from the app menu. If an app is already the latest version, the vendor has not shipped a fix yet.
- Docker images: rebuild on an updated base image, push and redeploy. Delete unused ones with `docker rmi IMAGE`.
- Node installed with nvm/fnm/volta: install the patched version with your version manager.
- Settings that turn off certificate verification: remove them.

### 1.5 Check again

```bash
bash emudhra-check.sh
```

Repeat until you get `RESULT: OK`, and again after every macOS update.

### 1.6 Useful options

| Command | What it does |
|---|---|
| `bash emudhra-check.sh --quick` | Skip the slow parts (macOS update check, disk scan, Docker). |
| `bash emudhra-check.sh --no-docker` | Skip the Docker image check. |
| `bash emudhra-check.sh --domain a.com,b.com` | Also check the certificates your own domains serve. |
| `bash emudhra-check.sh --log FILE` | Save the log to `FILE` instead of the Desktop. |
| `bash emudhra-check.sh --help` | All options. |

For MDM or scripts (run as the logged-in user): `bash emudhra-check.sh --fix --yes` applies the fixes without asking and skips the optional ones; add `--with-optional` to apply those too. Exit code `0` = no `FAIL`, `1` = at least one `FAIL`.

### 1.7 Undo

- `/etc/ssl/cert.pem`: see [step 2.4](#24-restore-only-if-something-breaks).
- Java `blocked.certs` or a custom CA file: copy the `*.pre-emudhra` file next to it back over it (with `sudo` if the file is system-wide).
- Everything else `--fix` does is an update (`brew upgrade`, `pip install --upgrade`, a tool's own updater), so there is nothing to undo.

---

## 2. `fix-certpem.sh`: `/etc/ssl/cert.pem` only

`fix-certpem.sh` removes the compromised eMudhra roots from `/etc/ssl/cert.pem`, the file Apple's built-in `curl`, `git`, `python3`, `perl`, `ruby` and `openssl` trust ([Apple's steps](https://support.apple.com/en-us/149555)). A macOS update can put the roots back, so check after every update until Apple ships its fix.

Without git:

```bash
curl -fsSL https://raw.githubusercontent.com/infraspecdev/emudhra-check/main/fix-certpem.sh -o fix-certpem.sh
chmod +x fix-certpem.sh
```

### 2.1 Check (any time, no password)

```bash
./fix-certpem.sh --check
```

| Output | Meaning |
|---|---|
| `does not contain the emSign roots.` | Fixed. Nothing to do. |
| `still contains: emSign ECC Root CA - G3` (and/or `AAA Certificate Services`) | Not fixed: run step 2.2. |

For a check of the whole Mac, see [part 1](#1-emudhra-checksh-check-the-whole-mac).

### 2.2 Fix

```bash
sudo ./fix-certpem.sh --with-aaa    # remove emSign ECC Root CA - G3 and AAA Certificate Services
./fix-certpem.sh --check            # expect: does not contain the emSign roots
```

- It backs up the file to `/etc/ssl/cert.pem.orig` first, and puts the file back by itself if `openssl` cannot read the result.
- `does not contain …` for every root means the file was already fixed: nothing changed, and no backup is taken.
- Without `--with-aaa` it keeps `AAA Certificate Services`: fewer sites can break, but the Sectigo cross-signed copies of the compromised intermediates are not blocked. See [step 2.5](#25-before-using---with-aaa-test-the-hosts-you-use-optional).

### 2.3 After every macOS update

```bash
sw_vers -productVersion
./fix-certpem.sh --check
```

If it lists the roots again, the update replaced the file (macOS 27.2 does this). Run step 2.2 again. The script takes a fresh backup from the new Apple file by itself; there is no need to delete the old one.

### 2.4 Restore (only if something breaks)

Restore only if Apple's `curl`, `git`, `python3`, `perl`, `ruby` or `openssl` now fail on a site you need with a certificate error (`unable to get local issuer certificate`, `certificate verify failed`). Safari, browsers, other apps and Homebrew tools do not use this file and are not affected.

```bash
sudo ./fix-certpem.sh --restore     # puts back /etc/ssl/cert.pem.orig (Apple's file)
sudo ./fix-certpem.sh               # optional: fix again but keep AAA Certificate Services
```

If an older version of `emudhra-check.sh` fixed the file, its backup is `/etc/ssl/cert.pem.pre-emudhra` and there is no `cert.pem.orig` until `fix-certpem.sh` has removed something once. Restore that backup instead:

```bash
sudo cp -p /etc/ssl/cert.pem.pre-emudhra /etc/ssl/cert.pem
```

### 2.5 Before using `--with-aaa`: test the hosts you use (optional)

Makes a copy of Apple's file without `AAA Certificate Services` and checks each host with it. Nothing on the Mac is changed. Put the hosts you depend on (git servers, APIs, package mirrors) in the list.

```bash
src=/etc/ssl/cert.pem
for b in /etc/ssl/cert.pem.orig /etc/ssl/cert.pem.pre-emudhra; do [ -f "$b" ] && src=$b && break; done
awk -v m="/CN=AAA Certificate Services" '/^(###|===) /{skip=0} /^=== / && substr($0,length($0)-length(m)+1)==m{skip=1} !skip' "$src" > /tmp/noaaa.pem
for h in github.com pypi.org your-git-server.example.com; do
  echo | openssl s_client -connect "$h:443" -servername "$h" -CAfile /tmp/noaaa.pem 2>/dev/null \
    | grep -q 'Verify return code: 0' && echo "OK    $h" || echo "BREAK $h"
done
```

`OK` for every host: `--with-aaa` is safe for you. `BREAK`: that host would fail in Apple's tools.

### 2.6 Optional: git, protected across macOS updates

macOS updates do not touch Homebrew's CA bundle, so pointing git at it keeps git protected even when an update puts the roots back in `/etc/ssl/cert.pem` (needs `brew install ca-certificates`, kept up to date with `brew upgrade`):

```bash
git config --global http.sslCAInfo /opt/homebrew/etc/ca-certificates/cert.pem
```

This covers git only. Apple's `curl`, `python3` and the other tools still need step 2.3 after each update.
