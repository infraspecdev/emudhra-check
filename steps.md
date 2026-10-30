# /etc/ssl/cert.pem: steps

`fix-certpem.sh` removes the compromised eMudhra roots from `/etc/ssl/cert.pem`, the file Apple's built-in `curl`, `git`, `python3`, `perl`, `ruby` and `openssl` trust ([Apple's steps](https://support.apple.com/en-us/149555)). A macOS update can put the roots back, so check after every update until Apple ships its fix.

Get the scripts once, then run every command below from that folder:

```bash
git clone https://github.com/infraspecdev/emudhra-check.git
cd emudhra-check
git pull                        # later: get the latest scripts
```

Without git:

```bash
curl -fsSL https://raw.githubusercontent.com/infraspecdev/emudhra-check/main/fix-certpem.sh -o fix-certpem.sh
chmod +x fix-certpem.sh
```

## 1. Check (any time, no password)

```bash
./fix-certpem.sh --check
```

| Output | Meaning |
|---|---|
| `does not contain the emSign roots.` | Fixed. Nothing to do. |
| `still contains: emSign ECC Root CA - G3` (and/or `AAA Certificate Services`) | Not fixed: run step 2. |

Full check of the whole Mac (curl, git, Python, Node, Java, apps, Docker images; changes nothing). Run it as your normal user, not with `sudo`:

```bash
bash emudhra-check.sh
```

## 2. Fix

```bash
sudo ./fix-certpem.sh --with-aaa    # remove emSign ECC Root CA - G3 and AAA Certificate Services
./fix-certpem.sh --check            # expect: does not contain the emSign roots
```

- It backs up the file to `/etc/ssl/cert.pem.orig` first, and puts the file back by itself if `openssl` cannot read the result.
- `does not contain …` for every root means the file was already fixed: nothing changed, and no backup is taken.
- Without `--with-aaa` it keeps `AAA Certificate Services`: fewer sites can break, but the Sectigo cross-signed copies of the compromised intermediates are not blocked. See [step 5](#5-before-using---with-aaa-test-the-hosts-you-use-optional).

## 3. After every macOS update

```bash
sw_vers -productVersion
./fix-certpem.sh --check
```

If it lists the roots again, the update replaced the file (macOS 27.2 does this). Run step 2 again. The script takes a fresh backup from the new Apple file by itself; there is no need to delete the old one.

## 4. Restore (only if something breaks)

Restore only if Apple's `curl`, `git`, `python3`, `perl`, `ruby` or `openssl` now fail on a site you need with a certificate error (`unable to get local issuer certificate`, `certificate verify failed`). Safari, browsers, other apps and Homebrew tools do not use this file and are not affected.

```bash
sudo ./fix-certpem.sh --restore     # puts back /etc/ssl/cert.pem.orig (Apple's file)
sudo ./fix-certpem.sh               # optional: fix again but keep AAA Certificate Services
```

If an older version of `emudhra-check.sh` fixed the file, its backup is `/etc/ssl/cert.pem.pre-emudhra` and there is no `cert.pem.orig` until `fix-certpem.sh` has removed something once. Restore that backup instead:

```bash
sudo cp -p /etc/ssl/cert.pem.pre-emudhra /etc/ssl/cert.pem
```

## 5. Before using `--with-aaa`: test the hosts you use (optional)

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

## 6. Optional: git, protected across macOS updates

macOS updates do not touch Homebrew's CA bundle, so pointing git at it keeps git protected even when an update puts the roots back in `/etc/ssl/cert.pem` (needs `brew install ca-certificates`, kept up to date with `brew upgrade`):

```bash
git config --global http.sslCAInfo /opt/homebrew/etc/ca-certificates/cert.pem
```

This covers git only. Apple's `curl`, `python3` and the other tools still need step 3 after each update.
