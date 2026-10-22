# emudhra-check

[English](README.md) | **Tiếng Việt** | [日本語](README.ja.md)

Chỉ cần chạy một lệnh để biết máy Mac của bạn còn tin các CA **eMudhra** đã bị lộ khoá hay không. Script cũng cho biết chính xác cần cập nhật những gì.

> **Bối cảnh.** Ngày 20/10/2026, khoá riêng của 8 chứng chỉ CA trung gian của eMudhra bị phát hiện đã bị lộ. Ai có các khoá này đều có thể giả mạo bất kỳ website nào đối với phần mềm còn tin chúng. Trình duyệt đã được bảo vệ, nhưng nhiều chương trình khác trên Mac giữ bản danh sách chứng chỉ tin cậy riêng: curl, git, Python, pip, Node.js, Java, app Electron và Docker image. Các bản đó cần được cập nhật riêng. Thông báo đầy đủ: https://emudhra.we-have-a-problem.com/

---

## Bắt đầu nhanh

1. Mở **Terminal**: bấm `⌘ Space`, gõ `Terminal`, rồi bấm Enter.
2. Dán dòng sau và bấm Enter:

   ```bash
   curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash
   ```

3. Đợi khoảng 1 phút cho đến khi thấy `RESULT:`.
   - `RESULT: OK`: không cần làm gì.
   - `RESULT: NOT OK`: xem bước 4.
4. Sửa những gì script tìm thấy. Có hai cách:
   - **Tự động.** Chạy lại với `--fix`. Script liệt kê các mục nó sửa được và hỏi `Apply these fixes now? [y/N]`. Có thể nó sẽ hỏi mật khẩu máy (admin). Sau đó nó sửa và kiểm tra lại toàn bộ:

     ```bash
     curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash -s -- --fix
     ```

   - **Tự làm.** Làm theo danh sách **What to do** ở cuối kết quả. Mỗi dòng ghi rõ cần cập nhật gì và làm thế nào.
5. File log được lưu trên **Desktop** (`emudhra-check-<tên máy>-<ngày>.log`, và thêm `...-after-fix.log` sau khi chạy `--fix`). Gửi file này cho IT khi được yêu cầu.

Một số việc luôn phải tự làm: cài bản cập nhật macOS/Safari, cập nhật các app như Slack hay VS Code, và build lại Docker image. Làm xong thì chạy kiểm tra lại cho đến khi thấy `RESULT: OK`.

---

## Chạy có an toàn không?

Có. Mặc định (chế độ kiểm tra, dry-run) script **chỉ đọc**.

- Script **không** thay đổi, cài đặt hay xoá gì. Nó không hỏi mật khẩu và không cần `sudo`.
- Script **không** cần git, Xcode, Homebrew hay Python. Nó chỉ dùng các công cụ có sẵn trong macOS và bỏ qua những gì máy bạn không có.
- Script **không** gửi dữ liệu của bạn đi đâu. Lưu lượng mạng duy nhất là các kết nối TLS tới 12 server thử nghiệm của advisory và tới `github.com` / `pypi.org` để xác nhận các site bình thường vẫn hoạt động.
- Script chỉ ghi ra file log trên Desktop và một thư mục tạm chứa các chương trình kiểm tra nhỏ. Thư mục tạm được xoá khi script chạy xong.
- Một ngoại lệ, chỉ khi Docker đang chạy: để đọc file CA bên trong mỗi image trên máy, script tạo một container ở trạng thái dừng từ image đó (không bao giờ khởi động nó) rồi xoá ngay. Dùng `--no-docker` để bỏ qua bước này.

Ở chế độ kiểm tra, các bản sửa chỉ được **gợi ý**. Chúng chỉ được áp dụng khi bạn chạy với `--fix` **và** trả lời `y`. Xem [Chế độ tự sửa](#chế-độ-tự-sửa---fix).

### Đọc trước khi chạy

Tải về, đọc, rồi mới chạy:

```bash
curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh -o emudhra-check.sh
less emudhra-check.sh            # đọc
bash emudhra-check.sh            # chạy
```

Script là một file duy nhất, chia thành các phần, mỗi phần bắt đầu bằng một dòng `# ====`. Danh sách các phần nằm ở đầu file. Nên xem ở đâu:

| Phần | Nội dung |
|---|---|
| Phần đầu file | Script đọc gì, kết nối tới đâu, thay đổi gì, và danh sách các phần |
| "Advisory data" | Dữ liệu từ advisory: server thử nghiệm, dấu hiệu nhận biết các root, 16 fingerprint, các phiên bản đã vá |
| "Step 1" … "Step 13" | Mỗi bước kiểm tra là một hàm |
| "Automatic fixes" | **Mọi thay đổi mà `--fix` có thể làm**, mỗi thay đổi là một hàm `fix_*`, kèm cách hoàn tác |
| "Probe programs" | 4 chương trình nhỏ (Python, Node.js, Java, JavaScript của macOS) mở các kết nối thử nghiệm |

---

## Script quyết định như thế nào

Advisory dựng **12 server thử nghiệm**. Mỗi server trình ra một chứng chỉ được ký bởi một trong các CA bị lộ:

```
dv-g3b-emudhra.we-have-a-problem.com      dv-g3b-aaa-emudhra.we-have-a-problem.com
ov-g3b-emudhra.we-have-a-problem.com      ov-g3b-aaa-emudhra.we-have-a-problem.com
ev-g3b-emudhra.we-have-a-problem.com      ev-g3b-aaa-emudhra.we-have-a-problem.com
dv-g3c-emudhra.we-have-a-problem.com      dv-g3c-aaa-emudhra.we-have-a-problem.com
ov-g3c-emudhra.we-have-a-problem.com      ov-g3c-aaa-emudhra.we-have-a-problem.com
ev-g3c-emudhra.we-have-a-problem.com      ev-g3c-aaa-emudhra.we-have-a-problem.com
```

Với mỗi chương trình tìm thấy, script thực sự kết nối tới cả 12 server:

- Chương trình **an toàn** từ chối mọi kết nối với lỗi chứng chỉ. Nó cũng phải vẫn kết nối được tới một site bình thường (`github.com`). Điều này chứng minh bản sửa không làm hỏng HTTPS bình thường.
- Chương trình **có lỗ hổng** kết nối thành công tới một hoặc nhiều server thử nghiệm. Chương trình đó cũng sẽ chấp nhận chứng chỉ giả được tạo bằng các khoá bị lộ.

Với những thứ không thể kiểm tra trực tiếp, script đọc phiên bản hoặc file chứng chỉ thay thế: phiên bản công cụ, app Electron, file CA trên đĩa và Docker image. Nó so sánh với bảng "Who has patched?" của advisory, hoặc tìm các root certificate bị ảnh hưởng bên trong file.

---

## Những gì được kiểm tra

| Bước | Gì | Kiểm tra thế nào | Nếu FAIL |
|---|---|---|---|
| 1 | **Kết nối** | Máy có tới được 12 server thử nghiệm không? Có cấu hình proxy không? | Chỉ là cảnh báo. Trên mạng bị chặn, kết quả kiểm tra trực tiếp có thể không kết luận được. |
| 2 | **macOS** | Bản cập nhật macOS đang chờ (`softwareupdate -l`). Kiểm tra trực tiếp trust store của chính macOS (Safari và app native dùng nó; curl/git/python3 của Apple, git của Homebrew và pip 24.2+ cũng dựa vào nó). Thiết lập tin cậy tuỳ chỉnh trong Keychain cho chứng chỉ eMudhra/emSign/AAA. `/etc/ssl/cert.pem` còn chứa các root bị ảnh hưởng không: curl, git, python3, perl và ruby có sẵn của Apple dùng file này, và cập nhật macOS không sửa nó. Phiên bản trình duyệt chỉ để tham khảo. | Cài bản cập nhật và khởi động lại. Nếu chính macOS vẫn tin các chain (Apple chưa chặn intermediate G3B kể cả trên macOS 27.0.1), `--fix` đánh dấu chúng là Never Trust trong login keychain; công cụ nào chỉ FAIL vì macOS sẽ được chỉ về bản sửa đó. Chạy bản sửa `/etc/ssl/cert.pem` của advisory (được in đầy đủ). Gỡ thiết lập tin cậy trong Keychain. |
| 3 | **curl** | Mọi curl trên máy (`/usr/bin/curl` của Apple, curl của Homebrew, các bản khác trong PATH) kết nối tới 12 server thử nghiệm. | Bản sửa `/etc/ssl/cert.pem`, hoặc `brew upgrade ca-certificates curl` |
| 4 | **git** | `git ls-remote` qua HTTPS tới 12 server thử nghiệm, với từng git. Bỏ qua nếu không cài git. | Giống curl. Kiểm tra `http.sslCAInfo`. |
| 5 | **Python** | Với mỗi Python 3 (Apple, Homebrew, python.org, pyenv, uv, conda, mise, asdf): (a) context `ssl` mặc định, dùng bởi `urllib`; (b) **certifi**, dùng bởi `requests`/`httpx`, kiểm tra trực tiếp và kiểm tra file; (c) **pip**, thử `pip download` thật. | Nâng `certifi` lên 2026.10.19 trở lên và `pip` lên 26.2.2 trở lên. Với pip của Apple, bản sửa `PIP_CERT` của advisory được in ra. |
| 6 | **Node.js** | Mọi bản Node (Homebrew, nvm, fnm, volta, asdf, mise): kiểm tra trực tiếp và kiểm tra phiên bản. Đã vá: 22.23.4, 24.22.1, 26.12.1. | Nâng cấp Node. |
| 7 | **Java** | Mọi JDK (`/usr/libexec/java_home`, SDKMAN, Homebrew, runtime của IDE trong /Applications): kiểm tra trực tiếp và kiểm tra `blocked.certs`. Đã vá: 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1. | Nâng cấp JDK, hoặc thêm 16 fingerprint vào `blocked.certs`. |
| 8 | **Công cụ khác** | Phiên bản của Homebrew `ca-certificates` (và các file `cert.pem` của nó), uv, pixi, rustup, deno, mise, bun, Go, Claude Code và Perl Mozilla::CA. | Lệnh nâng cấp được in ra cho từng công cụ. |
| 9 | **App Electron** | Với mỗi app trong /Applications xây trên Electron (Slack, VS Code, Discord, Notion, Postman…): phiên bản Electron của nó. Đã vá: 42.11.16, 43.8.1, 44.9.1 trở lên. | Cập nhật app. Nếu đã là bản mới nhất thì hãng chưa ra bản sửa; kiểm tra lại sau. |
| 10 | **Thiết lập TLS** | Các thiết lập tắt kiểm tra chứng chỉ (`NODE_TLS_REJECT_UNAUTHORIZED=0`, `PYTHONHTTPSVERIFY=0`, `GIT_SSL_NO_VERIFY`, `insecure` trong `~/.curlrc`, `strict-ssl=false` trong `~/.npmrc`, `sslVerify=false` trong `~/.gitconfig`, `trusted-host` của pip). File CA tuỳ chỉnh đặt qua `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`, `PIP_CERT`, git `http.sslCAInfo` hoặc npm `cafile`. | Gỡ thiết lập, hoặc thay file CA cũ. |
| 11 | **File CA trên đĩa** | Tìm trong thư mục home, Homebrew, Python của python.org và conda các file CA bundle (`cacert.pem`, `cert.pem`, `ca-bundle.crt`…). Mỗi file được kiểm tra xem còn các root bị ảnh hưởng không. Bước này tìm ra các bản `certifi` cũ trong virtualenv và các bản sao đóng gói kèm. Bỏ qua `~/Library`, cache và `node_modules` (thêm `--deep` để quét cả `node_modules`). | Nâng `certifi`/pip trong virtualenv đó, hoặc xoá môi trường nếu không dùng nữa. File còn sót lại từ một bản Python đã gỡ được báo WARN: xoá đi nếu không còn gì dùng. |
| 12 | **Docker image** | Nếu Docker đang chạy: đọc CA bundle hệ thống bên trong mỗi image trên máy mà không chạy image. | Build lại trên base image đã cập nhật (`apt-get`/`apk`/`dnf upgrade ca-certificates`), rồi push và deploy lại. Cập nhật Mac không cập nhật container. |
| 13 | **Domain của bạn** | Chỉ khi có `--domain`: tải chuỗi chứng chỉ server của bạn trả về và kiểm tra nó không dùng CA trung gian eMudhra bị ảnh hưởng. | Thay chứng chỉ. |

---

## Đọc kết quả

Mỗi mục kiểm tra in ra một dòng: icon và trạng thái, tên mục, chi tiết và thời gian kiểm tra. Dòng `↳` đi kèm ghi cách sửa khi bạn cần xử lý. Trên màn hình, dòng dài được rút gọn cho vừa cửa sổ; file log luôn có đầy đủ nội dung.

```
━━ 3/13  curl ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 10:42:05
   Each curl binary must reject all 12 test chains.
  ❌ FAIL  curl /usr/bin/curl (8.7.1 LibreSSL/3.3.6) · TRUSTS 6/12 compromised test chai…  1.9s
           ↳ Apply the /etc/ssl/cert.pem fix from step 2 (macOS updates do not update that file).
  ✅ PASS  curl /opt/homebrew/opt/curl/bin/curl (8.10.1 OpenSSL/3.4.0) · rejected 12/12 …  1.7s
   └ step done in 3.6s
```

*(Ví dụ minh hoạ. Kết quả của script luôn bằng tiếng Anh.)*

| Trạng thái | Ý nghĩa |
|---|---|
| ✅ `PASS` | An toàn. |
| ❌ `FAIL` | **Phải sửa.** Chương trình này vẫn tin các CA bị lộ, hoặc là phiên bản chưa có bản vá. |
| 🟡 `WARN` | Script không kết luận được (ví dụ không có mạng tới server thử nghiệm), hoặc có gì đó cần xem. Đọc phần chi tiết. |
| ⚪ `SKIP` | Không cài hoặc không áp dụng. Không cần làm gì. |
| 🔵 `INFO` | Chỉ để tham khảo. |

Cuối cùng bạn nhận được:

- **bảng tổng kết** mỗi bước một dòng: bao nhiêu mục ✅ / ❌ / 🟡 / ⚪ và bước đó mất bao lâu;
- danh sách **What to do** chỉ gồm những gì bạn cần xử lý. Các mục cùng một cách sửa được gộp chung một dòng;
- `RESULT: OK` hoặc `RESULT: NOT OK`;
- danh sách những gì `--fix` có thể tự sửa, và đường dẫn file log.

File log là văn bản thuần, mỗi mục kiểm tra một dòng (`[PASS]`, `[FAIL]`…), có đầy đủ chi tiết và kết quả với từng server trong 12 server thử nghiệm. Gửi cho IT khi được yêu cầu. Khi dùng `--no-color`, hoặc khi output không phải terminal, màn hình hiện đúng định dạng thuần như file log.

---

## Chế độ tự sửa (`--fix`)

```bash
curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash -s -- --fix
```

1. Chạy toàn bộ các bước kiểm tra trước, giống chế độ kiểm tra.
2. Script liệt kê mọi bản sửa nó áp dụng được. Bản sửa cần mật khẩu admin được đánh dấu 🔑 `admin password`.
3. Script hỏi `Apply these fixes now? [y/N]`. Không có gì thay đổi nếu bạn không trả lời `y`.
4. Nó áp dụng từng bản sửa và in ✅ `DONE`, ❌ `FAILED` hoặc ⚪ `SKIP` kèm thời gian. Toàn bộ output của lệnh được ghi vào log.
5. Nó **chạy lại toàn bộ kiểm tra** và lưu kết quả vào `...-after-fix.log`, để bạn thấy những gì đã được sửa.

| Vấn đề | Cách tự sửa | Cần mật khẩu |
|---|---|---|
| `/etc/ssl/cert.pem` còn các root bị ảnh hưởng (curl/git/python3 của Apple) | Cách xử lý tạm của advisory: gỡ 2 root. Bản gốc được giữ ở `/etc/ssl/cert.pem.pre-emudhra`. | có |
| Trust store của macOS vẫn tin các chain thử nghiệm (Safari, curl/git/python3 của Apple, git của Homebrew, pip 24.2+) | Tải các intermediate mà server thử nghiệm gửi về và đánh dấu **Never Trust** trong login keychain những cert có SHA-256 nằm trong danh sách của advisory. Hoàn tác: xoá các chứng chỉ `EM … CA - G3x` trong Keychain Access > login. | mật khẩu đăng nhập (hộp thoại macOS) |
| pip có sẵn của Apple tin các server thử nghiệm | Đặt `PIP_CERT=/etc/ssl/cert.pem` trong `usercustomize.py` của user (tác dụng như `sitecustomize.py` của advisory, nhưng macOS không chặn) | không |
| Homebrew ca-certificates / curl / git / node / python / uv / mise đã cũ | `brew update`, rồi `brew upgrade` từng formula, chạy dưới quyền bạn. Formula nào lỗi, hoặc bị Homebrew ngừng hỗ trợ (ví dụ `python@3.8`), không làm dừng các formula khác. | không |
| certifi hoặc pip cũ trong virtualenv, pyenv, conda hoặc Python của python.org | `python -m pip install --upgrade 'certifi>=2026.10.19'` / `'pip>=26.2.2'`. Với virtualenv tạo bằng uv (không có pip): `uv pip install`. Với certifi cài bằng pip vào Python của Homebrew: thêm `--break-system-packages`. | không |
| Python của python.org không kiểm tra được site nào | Chạy `Install Certificates.command` của nó | không |
| Java tin các server thử nghiệm | Thêm 16 fingerprint bị lộ vào `blocked.certs` / `blacklisted.certs` của JDK (JDK của Homebrew thì thêm `brew upgrade`). Bản gốc được giữ ở `*.pre-emudhra`. Java nằm trong app (Android Studio, IntelliJ…) không bị sửa: hãy cập nhật app. | nếu JDK cài cho toàn hệ thống |
| uv, pixi, rustup, deno, mise, Claude Code đã cũ | Lệnh tự cập nhật của chính chúng | không |

Những mục sau **không** được sửa tự động. Script sẽ cho biết cần làm gì:

- cập nhật macOS và Safari, vì cần khởi động lại;
- app Electron (Slack, VS Code…): cập nhật từ trong app;
- Docker image: build lại và deploy lại;
- Node cài bằng nvm/fnm/volta: cài bản đã vá bằng trình quản lý phiên bản của bạn;
- thiết lập tắt kiểm tra chứng chỉ: tự gỡ.

Để hoàn tác thay đổi `/etc/ssl/cert.pem`: `sudo cp -p /etc/ssl/cert.pem.pre-emudhra /etc/ssl/cert.pem`. Để hoàn tác thay đổi Java, chép file `.pre-emudhra` trở lại theo cách tương tự.

Với MDM hoặc script, `--fix --yes` áp dụng bản sửa mà không hỏi. Cần chạy dưới quyền người dùng đang đăng nhập. Các bản sửa cần sudo sẽ bị bỏ qua nếu không có sudo.

---

## Tốc độ

Mọi kiểm tra trực tiếp đều chạy song song: cả 12 server thử nghiệm cùng lúc cho mỗi chương trình, và các kiểm tra pip cũng chạy đồng thời. Hai phần chậm được khởi động ngầm ngay khi script bắt đầu: kiểm tra cập nhật macOS (`softwareupdate -l`) và quét đĩa. Một lần chạy thường mất khoảng 1 phút. Dùng `--quick` để bỏ qua kiểm tra cập nhật, quét đĩa và Docker.

---

## Tuỳ chọn

```bash
curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash -s -- --quick
```

| Tuỳ chọn | Tác dụng |
|---|---|
| *(không có)* | Chỉ kiểm tra (dry-run). Không thay đổi gì. |
| `--fix` | Kiểm tra, đề xuất áp dụng các bản tự sửa, rồi kiểm tra lại. |
| `--yes` | Dùng với `--fix`: không hỏi xác nhận. |
| `--quick` | Bỏ qua các phần chậm: kiểm tra cập nhật macOS, quét đĩa và Docker. |
| `--no-scan` | Bỏ qua bước 11, quét file CA. |
| `--no-docker` | Bỏ qua bước 12, Docker. |
| `--deep` | Quét cả thư mục `node_modules` (chậm hơn). |
| `--domain a.com,b.com` | Kiểm tra thêm chứng chỉ mà domain của bạn trả về (bước 13). |
| `--log FILE` | Lưu log vào `FILE` thay vì Desktop. |
| `--no-color` | Output thuần, không màu và không icon. |
| `--help` | Hiện hướng dẫn. |

Mã thoát: `0` = không có FAIL, `1` = có ít nhất một FAIL. Có thể dùng trong script hoặc MDM.

---

## Câu hỏi thường gặp

**Tôi đã cập nhật macOS. Sao `/usr/bin/curl` vẫn FAIL?**
curl, git và python3 có sẵn của Apple kiểm tra chứng chỉ dựa trên file `/etc/ssl/cert.pem`, và file đó không được cập nhật. Script in ra bản sửa của advisory, cần mật khẩu admin. Bản cập nhật macOS sau có thể khôi phục file cũ, nên hãy chạy kiểm tra lại sau mỗi lần cập nhật.

**Tắt kiểm tra chứng chỉ được không?**
Không. Làm vậy còn tệ hơn nhiều. Advisory nói rõ không được tắt kiểm tra.

**Tôi dùng VPN hoặc phần mềm bảo mật (Cloudflare WARP, Zscaler, web shield của antivirus…).**
Các công cụ soi lưu lượng HTTPS ký lại chứng chỉ, có thể che hoặc làm sai kết quả. Nếu kết quả bất thường, tắt chúng trong lúc chạy rồi thử lại.

**Hầu hết đều WARN và báo "network errors".**
Có thể mạng của bạn chặn các server thử nghiệm (một số mạng văn phòng làm vậy), hoặc bạn đang offline. Chạy lại trên mạng khác, ví dụ hotspot điện thoại.

**Một app tôi dùng bị FAIL dù đã là bản mới nhất.**
Hãng chưa ra bản cập nhật Electron. Giữ app luôn cập nhật và kiểm tra lại sau.

**Script có kiểm tra server và workload Kubernetes của tôi không?**
Không. Bước 12 chỉ kiểm tra Docker image trên máy Mac này, và bước 13 chỉ kiểm tra chứng chỉ domain của bạn trả về. Server và container trên production cần được cập nhật và deploy lại riêng.

---

## Phát triển

Sửa trực tiếp file `emudhra-check.sh`. Trước khi push, kiểm tra `shellcheck emudhra-check.sh` không báo gì và script chạy được với bash 3.2 có sẵn trong macOS (`/bin/bash emudhra-check.sh`). Hãy giữ code tương thích với bash 3.2: không dùng mảng kết hợp (associative array), không dùng `mapfile`, không dùng `${var,,}`.

---

## Nguồn dữ liệu

Các server thử nghiệm, dấu hiệu nhận biết root certificate, 16 fingerprint chứng chỉ bị lộ và các phiên bản đã vá lấy từ advisory và repo nguồn của nó:

- https://emudhra.we-have-a-problem.com/
- https://github.com/galadran/we-have-a-problem.com (`chains/`, `roots.json`, `impacted-intermediates.json`)

Nếu bảng "Who has patched?" của advisory thay đổi, cập nhật các giá trị `FIX_*` trong phần "Advisory data" của `emudhra-check.sh`.
