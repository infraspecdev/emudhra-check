# emudhra-check

[English](README.md) | [Tiếng Việt](README.vi.md) | **日本語**

コマンド 1 つで、お使いの Mac が鍵の漏えいした **eMudhra** の認証局 (CA) をまだ信頼しているかどうかを調べます。何をアップデートすればよいかも具体的に表示します。

> **背景** 2026 年 10 月 20 日、eMudhra の中間 CA 証明書 8 枚の秘密鍵が漏えいしていることが判明しました。この鍵を持つ人は、それをまだ信頼しているソフトウェアに対して、どんな Web サイトにもなりすますことができます。ブラウザはすでに対策済みですが、Mac 上の多くのプログラムは信頼する証明書の一覧を独自に持っています。curl、git、Python、pip、Node.js、Java、Electron アプリ、Docker イメージなどです。これらは個別にアップデートする必要があります。アドバイザリー全文: https://emudhra.we-have-a-problem.com/

スクリプトの出力は英語です。各ステータスの意味は下の[出力の見方](#出力の見方)を参照してください。

---

## クイックスタート

1. **ターミナル**を開きます。`⌘ Space` を押して `Terminal` と入力し、Enter を押します。
2. 次の 1 行を貼り付けて Enter を押します。

   ```bash
   curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash
   ```

3. `RESULT:` が表示されるまで 1 分ほど待ちます。初期設定ではチェックだけを行い、Mac には何も変更を加えません。
   - `RESULT: OK`: 対応は不要です。
   - `RESULT: NOT OK`: 手順 4 に進みます。
4. 見つかった問題を修正します。方法は 2 つあります。
   - **自動で修正する。** `--fix` を付けてもう一度実行します。スクリプトが自動で適用できる修正の一覧を表示し、`Apply these fixes now? [y/N]` と確認します。Mac のパスワード (管理者) を聞かれることもあります。修正が終わると、すべてをもう一度チェックします。

     ```bash
     curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash -s -- --fix
     ```

   - **手動で修正する。** 出力の最後にある **What to do** の一覧に従います。各行に、何をどうアップデートするかが書かれています。
5. ログファイルが**デスクトップ**に保存されます (`emudhra-check-<コンピュータ名>-<日付>.log`。`--fix` の後は `...-after-fix.log` も)。IT 担当から求められたら送ってください。

次の作業は必ずご自身で行う必要があります。macOS / Safari のアップデートのインストール、Slack や VS Code などのアプリのアップデート、Docker イメージの再ビルドです。作業が終わったら、`RESULT: OK` になるまでもう一度チェックを実行してください。

---

## 実行しても安全ですか?

はい。初期設定 (チェックのみ、いわゆる dry-run) では、スクリプトは**読み取りだけ**を行います。

- 何かを変更、インストール、削除することは**ありません**。パスワードを聞いたり `sudo` を使ったりもしません。
- git、Xcode、Homebrew、Python は**不要**です。macOS に標準で入っているツールだけを使い、インストールされていないものはスキップします。
- データをどこかに送信することは**ありません**。ネットワーク通信は、アドバイザリーの 12 台のテストサーバーへの TLS 接続と、通常のサイトに問題なくつながることを確認するための `github.com` / `pypi.org` への接続だけです。
- 書き込むファイルは、デスクトップのログだけです。
- 例外が 1 つあります。Docker が起動している場合に限り、各ローカルイメージ内の CA ファイルを読むために、イメージから停止状態のコンテナを作成し (起動はしません)、すぐに削除します。これを行わないようにするには `--no-docker` を付けます。

チェックモードでは、修正は**提案されるだけ**です。修正が適用されるのは、`--fix` を付けて実行し、**さらに** `y` と答えたときだけです。詳しくは[自動修正モード](#自動修正モード---fix)を参照してください。

実行する前にスクリプトの中身を読みたい場合は、次のようにします。

```bash
curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh -o emudhra-check.sh
less emudhra-check.sh        # 読む
bash emudhra-check.sh        # 実行する
```

---

## 判定のしくみ

アドバイザリーは **12 台のテストサーバー**を公開しています。どのサーバーも、漏えいした CA のいずれかで署名された証明書を提示します。

```
dv-g3b-emudhra.we-have-a-problem.com      dv-g3b-aaa-emudhra.we-have-a-problem.com
ov-g3b-emudhra.we-have-a-problem.com      ov-g3b-aaa-emudhra.we-have-a-problem.com
ev-g3b-emudhra.we-have-a-problem.com      ev-g3b-aaa-emudhra.we-have-a-problem.com
dv-g3c-emudhra.we-have-a-problem.com      dv-g3c-aaa-emudhra.we-have-a-problem.com
ov-g3c-emudhra.we-have-a-problem.com      ov-g3c-aaa-emudhra.we-have-a-problem.com
ev-g3c-emudhra.we-have-a-problem.com      ev-g3c-aaa-emudhra.we-have-a-problem.com
```

スクリプトは、見つけたプログラムごとに、実際に 12 台すべてのサーバーへ接続します。

- **安全な**プログラムは、すべての接続を証明書エラーで拒否します。さらに、通常のサイト (`github.com`) には接続できる必要があります。これで、修正によって普段の HTTPS が壊れていないことを確認します。
- **影響を受ける**プログラムは、1 台以上のテストサーバーに接続できてしまいます。そのプログラムは、漏えいした鍵で作られた偽の証明書も受け入れてしまいます。

実際に接続してテストできないものは、代わりにバージョンや証明書ファイルを調べます。対象はツールのバージョン、Electron アプリ、ディスク上の CA ファイル、Docker イメージです。アドバイザリーの「Who has patched?」の表と比較するか、ファイルの中に影響を受けるルート証明書が含まれているかを調べます。

---

## チェック内容

| ステップ | 対象 | チェック方法 | FAIL の場合 |
|---|---|---|---|
| 1 | **接続** | この Mac から 12 台のテストサーバーにつながるか。プロキシが設定されているか。 | 警告のみです。通信が遮断されたネットワークでは、接続テストの結果が判定できないことがあります。 |
| 2 | **macOS** | 保留中の macOS アップデート (`softwareupdate -l`)。キーチェーンで eMudhra / emSign / AAA の証明書に独自の信頼設定がないか。`/etc/ssl/cert.pem` に影響を受けるルートがまだ含まれていないか (Apple 標準の curl、git、python3、perl、ruby はこのファイルを使いますが、macOS のアップデートでは修正されません)。ブラウザのバージョンは参考として表示します。 | アップデートをインストールして再起動します。アドバイザリーの `/etc/ssl/cert.pem` の修正を実行します (コマンド全体が表示されます)。キーチェーンの信頼設定を元に戻します。 |
| 3 | **curl** | Mac 上のすべての curl (Apple の `/usr/bin/curl`、Homebrew の curl、PATH 上のその他) が 12 台のテストサーバーに接続します。 | `/etc/ssl/cert.pem` の修正、または `brew upgrade ca-certificates curl` |
| 4 | **git** | git ごとに、12 台のテストサーバーに対して HTTPS で `git ls-remote` を実行します。git がなければスキップします。 | curl と同じです。`http.sslCAInfo` も確認してください。 |
| 5 | **Python** | Python 3 ごと (Apple、Homebrew、python.org、pyenv、uv、conda、mise、asdf) に、(a) `urllib` が使う既定の `ssl` コンテキスト、(b) `requests` / `httpx` が使う **certifi** (接続テストとファイルのチェック)、(c) **pip** (実際に `pip download` を試行) を調べます。 | `certifi` を 2026.10.19 以降に、`pip` を 26.2.2 以降にアップグレードします。Apple の pip には、アドバイザリーの `PIP_CERT` の修正が表示されます。 |
| 6 | **Node.js** | すべての Node (Homebrew、nvm、fnm、volta、asdf、mise) で接続テストとバージョンチェックを行います。修正済み: 22.23.4、24.22.1、26.12.1。 | Node をアップグレードします。 |
| 7 | **Java** | すべての JDK (`/usr/libexec/java_home`、SDKMAN、Homebrew、/Applications 内の IDE のランタイム) で接続テストと `blocked.certs` のチェックを行います。修正済み: 8u511、11.0.33、17.0.21、21.0.13、25.0.5、27.0.1。 | JDK をアップグレードするか、16 個のフィンガープリントを `blocked.certs` に追加します。 |
| 8 | **その他のツール** | Homebrew の `ca-certificates` (とその `cert.pem` ファイル)、uv、pixi、rustup、deno、mise、bun、Go、Claude Code、Perl Mozilla::CA のバージョン。 | ツールごとにアップグレードのコマンドが表示されます。 |
| 9 | **Electron アプリ** | /Applications 内の Electron 製アプリ (Slack、VS Code、Discord、Notion、Postman など) ごとの Electron のバージョン。修正済み: 42.11.16、43.8.1、44.9.1 以降。 | アプリをアップデートします。すでに最新版の場合は、開発元がまだ修正版を出していません。後でもう一度チェックしてください。 |
| 10 | **TLS の設定** | 証明書の検証を無効にする設定 (`NODE_TLS_REJECT_UNAUTHORIZED=0`、`PYTHONHTTPSVERIFY=0`、`GIT_SSL_NO_VERIFY`、`~/.curlrc` の `insecure`、`~/.npmrc` の `strict-ssl=false`、`~/.gitconfig` の `sslVerify=false`、pip の `trusted-host`)。`SSL_CERT_FILE`、`REQUESTS_CA_BUNDLE`、`CURL_CA_BUNDLE`、`NODE_EXTRA_CA_CERTS`、`GIT_SSL_CAINFO`、`PIP_CERT`、git の `http.sslCAInfo`、npm の `cafile` で指定された独自の CA ファイル。 | その設定を削除するか、古い CA ファイルを置き換えます。 |
| 11 | **ディスク上の CA ファイル** | ホームフォルダ、Homebrew、python.org の Python、conda から CA バンドルファイル (`cacert.pem`、`cert.pem`、`ca-bundle.crt` など) を探し、影響を受けるルートが含まれていないか調べます。virtualenv 内の古い `certifi` や、同梱されたコピーが見つかります。`~/Library`、キャッシュ、`node_modules` はスキップします (`node_modules` も含めるには `--deep`)。 | その virtualenv の `certifi` / pip をアップグレードするか、使っていなければ環境ごと削除します。すでにアンインストールされた Python の残りファイルは WARN として表示されます。何も使っていなければ削除してください。 |
| 12 | **Docker イメージ** | Docker が起動していれば、各ローカルイメージ内のシステム CA バンドルを、イメージを実行せずに読み取ります。 | 更新済みのベースイメージで再ビルドし (`apt-get` / `apk` / `dnf upgrade ca-certificates`)、push して再デプロイします。Mac をアップデートしてもコンテナは更新されません。 |
| 13 | **自社のドメイン** | `--domain` を指定したときだけ、サーバーが返す証明書チェーンを取得し、影響を受ける eMudhra の中間 CA が使われていないか確認します。 | 証明書を差し替えます。 |

---

## 出力の見方

チェック 1 件につき 1 行が表示されます。アイコンとステータス、対象、詳細、チェックにかかった時間です。対応が必要な場合は、その下に修正方法を書いた `↳` の行が続きます。画面では長い行はウィンドウの幅に合わせて省略されますが、ログファイルには常に全文が記録されます。

```
━━ 3/13  curl ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 10:42:05
   Each curl binary must reject all 12 test chains.
  ❌ FAIL  curl /usr/bin/curl (8.7.1 LibreSSL/3.3.6) · TRUSTS 6/12 compromised test chai…  1.9s
           ↳ Apply the /etc/ssl/cert.pem fix from step 2 (macOS updates do not update that file).
  ✅ PASS  curl /opt/homebrew/opt/curl/bin/curl (8.10.1 OpenSSL/3.4.0) · rejected 12/12 …  1.7s
   └ step done in 3.6s
```

*(出力例。スクリプトの出力は常に英語です。)*

| ステータス | 意味 |
|---|---|
| ✅ `PASS` | 安全です。 |
| ❌ `FAIL` | **修正が必要です。** このプログラムは漏えいした CA をまだ信頼しているか、修正が入っていないバージョンです。 |
| 🟡 `WARN` | 判定できなかった (例: テストサーバーにつながらない) か、確認が必要な点があります。詳細を読んでください。 |
| ⚪ `SKIP` | インストールされていないか、対象外です。対応は不要です。 |
| 🔵 `INFO` | 参考情報です。 |

最後に次の内容が表示されます。

- ステップごとに 1 行の**サマリー**: ✅ / ❌ / 🟡 / ⚪ がそれぞれ何件か、そのステップにかかった時間;
- 対応が必要なものだけを並べた **What to do** の一覧。同じ修正で直るチェックは 1 行にまとめられます;
- `RESULT: OK` または `RESULT: NOT OK`;
- `--fix` で自動適用できる修正の一覧と、ログファイルのパス。

ログファイルはプレーンテキストで、チェック 1 件ごとに 1 行 (`[PASS]`、`[FAIL]` など)、詳細の全文、12 台のテストサーバーそれぞれの結果が記録されます。IT 担当から求められたら送ってください。`--no-color` を付けた場合や、出力先がターミナルでない場合は、画面にもログと同じプレーンな形式で表示されます。

---

## 自動修正モード (`--fix`)

```bash
curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash -s -- --fix
```

1. まず、チェックモードと同じようにすべてのチェックを実行します。
2. 自動で適用できる修正をすべて一覧表示します。管理者パスワードが必要な修正には 🔑 `admin password` と表示されます。
3. `Apply these fixes now? [y/N]` と確認します。`y` と答えない限り、何も変更されません。
4. 修正を 1 つずつ適用し、✅ `DONE`、❌ `FAILED`、⚪ `SKIP` のいずれかと所要時間を表示します。コマンドの出力はすべてログに記録されます。
5. **すべてのチェックをもう一度**実行し、結果を `...-after-fix.log` に保存します。何が直ったかを確認できます。

| 見つかった問題 | 自動修正の内容 | パスワード |
|---|---|---|
| `/etc/ssl/cert.pem` に影響を受けるルートが残っている (Apple の curl / git / python3) | アドバイザリーの回避策: 2 つのルートを削除します。元のファイルは `/etc/ssl/cert.pem.pre-emudhra` として残します。 | 必要 |
| Apple 標準の pip がテストサーバーを信頼している | アドバイザリーの `sitecustomize.py` の修正 (`PIP_CERT=/etc/ssl/cert.pem`) | 必要 |
| Homebrew の ca-certificates / curl / git / node / python / uv / mise が古い | `brew update` の後、formula ごとに `brew upgrade` を実行します (ご自身のユーザーで実行)。失敗した formula や、Homebrew で無効化された formula (`python@3.8` など) があっても、他の formula は続行します。 | 不要 |
| virtualenv、pyenv、conda、python.org の Python の certifi または pip が古い | `python -m pip install --upgrade 'certifi>=2026.10.19'` / `'pip>=26.2.2'`。pip のない uv の virtualenv では `uv pip install`。Homebrew の Python に pip で入れた certifi は `--break-system-packages` を付けて同様に実行します。 | 不要 |
| python.org の Python がどのサイトも検証できない | その Python の `Install Certificates.command` を実行します | 不要 |
| Java がテストサーバーを信頼している | 漏えいした 16 個のフィンガープリントを JDK の `blocked.certs` / `blacklisted.certs` に追加します。元のファイルは `*.pre-emudhra` として残します。 | JDK がシステム全体にインストールされている場合は必要 |
| uv、pixi、rustup、deno、mise、Claude Code が古い | 各ツール自身のセルフアップデートのコマンド | 不要 |

次のものは自動では**修正されません**。何をすればよいかはスクリプトが表示します。

- macOS と Safari のアップデート (再起動が必要なため);
- Electron アプリ (Slack、VS Code など): アプリからアップデートしてください;
- Docker イメージ: 再ビルドして再デプロイしてください;
- nvm / fnm / volta でインストールした Node: お使いのバージョンマネージャーで修正版をインストールしてください;
- 証明書の検証を無効にする設定: ご自身で削除してください。

`/etc/ssl/cert.pem` の変更を元に戻すには: `sudo cp -p /etc/ssl/cert.pem.pre-emudhra /etc/ssl/cert.pem`。Java の変更も同じように `.pre-emudhra` のファイルをコピーして戻せます。

MDM やスクリプトから使う場合、`--fix --yes` を付けると確認なしで修正を適用します。ログイン中のユーザーとして実行する必要があります。sudo が使えない場合、sudo が必要な修正はスキップされます。

---

## 速度

接続テストはすべて並列で実行します。プログラムごとに 12 台のテストサーバーへ同時に接続し、pip のチェックも同時に行います。時間のかかる 2 つの処理、macOS アップデートの確認 (`softwareupdate -l`) とディスクのスキャンは、スクリプト開始と同時にバックグラウンドで始まります。通常は 1 分ほどで終わります。`--quick` を付けると、アップデートの確認、ディスクのスキャン、Docker をスキップします。

---

## オプション

```bash
curl -fsSL https://raw.githubusercontent.com/wakumo/emudhra-check/main/emudhra-check.sh | bash -s -- --quick
```

| オプション | 内容 |
|---|---|
| *(なし)* | チェックのみ (dry-run)。何も変更しません。 |
| `--fix` | チェックし、自動修正の適用を提案し、もう一度チェックします。 |
| `--yes` | `--fix` と一緒に使い、確認なしで適用します。 |
| `--quick` | 時間のかかる処理 (macOS アップデートの確認、ディスクのスキャン、Docker) をスキップします。 |
| `--no-scan` | ステップ 11 (CA ファイルのスキャン) をスキップします。 |
| `--no-docker` | ステップ 12 (Docker) をスキップします。 |
| `--deep` | ディスクのスキャンに `node_modules` フォルダも含めます (遅くなります)。 |
| `--domain a.com,b.com` | 自社のドメインが提示する証明書もチェックします (ステップ 13)。 |
| `--log FILE` | ログをデスクトップではなく `FILE` に保存します。 |
| `--no-color` | 色やアイコンを使わないプレーンな出力にします。 |
| `--help` | ヘルプを表示します。 |

終了コード: `0` = FAIL なし、`1` = FAIL が 1 件以上。スクリプトや MDM で利用できます。

---

## よくある質問

**macOS をアップデートしたのに、`/usr/bin/curl` がまだ FAIL になるのはなぜですか?**
Apple 標準の curl、git、python3 は `/etc/ssl/cert.pem` というファイルで証明書を検証しますが、このファイルはアップデートされていません。スクリプトはアドバイザリーの修正を表示します (管理者パスワードが必要です)。今後の macOS アップデートで古いファイルに戻ることがあるので、アップデートのたびにチェックを実行してください。

**証明書の検証を無効にしてしまえばよいのでは?**
いいえ。状況がずっと悪くなります。アドバイザリーも、検証を無効にしないよう明記しています。

**VPN やセキュリティソフト (Cloudflare WARP、Zscaler、ウイルス対策ソフトの Web 保護など) を使っています。**
HTTPS の通信を検査するツールは証明書を再署名するため、結果が隠れたり変わったりすることがあります。結果がおかしいと感じたら、実行中だけそれらをオフにしてもう一度試してください。

**ほとんどの項目が WARN で、「network errors」と表示されます。**
ネットワークがテストサーバーへの接続を遮断している (一部のオフィスネットワークなど) か、オフラインの可能性があります。スマートフォンのテザリングなど、別のネットワークでもう一度実行してください。

**使っているアプリが FAIL ですが、すでに最新版です。**
開発元がまだ Electron のアップデートを出していません。アプリを最新に保ち、後でもう一度チェックしてください。

**サーバーや Kubernetes のワークロードもチェックしますか?**
いいえ。ステップ 12 はこの Mac 上の Docker イメージだけ、ステップ 13 は自社ドメインが提示する証明書だけをチェックします。本番環境のサーバーやコンテナは、別途アップデートして再デプロイする必要があります。

---

## データの出典

テストサーバー、ルート証明書の識別情報、漏えいした 16 個の証明書のフィンガープリント、修正済みバージョンは、アドバイザリーとそのソースリポジトリから取得しています。

- https://emudhra.we-have-a-problem.com/
- https://github.com/galadran/we-have-a-problem.com (`chains/`、`roots.json`、`impacted-intermediates.json`)

アドバイザリーの「Who has patched?」の表が変わった場合は、`emudhra-check.sh` の先頭付近にある `FIX_*` の値を更新してください。
