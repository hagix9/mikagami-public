# Mikagami

Mikagami は、Linux の 2 台のノードで Active/Standby の HA クラスタを作り、サービスと VIP（仮想 IP アドレス）を片方のノードだけで動かす、軽量の HA サービスマネージャーです。Pacemaker + Corosync より少ない設定で導入・運用できることを目指しています。安全を確かめられない時は、推測で動かずに止まります（fail-closed）。

版：0.8.0。ライセンス：Apache License 2.0。公式サイト：https://mikagami.fulltrust.co.jp

## できること

- 1 つのサービス、または複数の資源のグループ（例：データベース → アプリケーション → VIP）を、どちらか 1 台だけで動かす。
- VIP を付け、サービスの準備ができてから gratuitous ARP で公開する。
- 冷起動で、両ノードが健全な時に自動で Active を 1 台決める。
- 計画停止（`systemctl stop`）では、相手のノードに引き継ぐ。
- 相手のノードが失われた時は、独立した fencing の装置（電源、ハイパーバイザー、クラウドの制御面）で相手を止めたことを確かめてから引き継ぐ。通信が切れただけでは引き継がない。
- サービスのヘルスチェックを行い、異常の時に警告・ローカルの再起動・相手への切替から選べる（2 ノード構成）。
- `mikagami`（または同じ CLI の別名 `mkg`）で状態を確かめる。

Pacemaker の全機能（多数のノード、資源ごとの配置の制約、quorum の細かな設定など）は対象外です。

## 対応 OS と構成

| 項目 | 内容 |
|---|---|
| OS | Linux（systemd）。RPM は Rocky Linux 9 / 10 向け |
| 構成 | **2 ノード構成**（補助ノードなし）と、**補助ノード（Witness）付き構成**（2 台 + 第 3 のホスト） |
| サービスの管理 | `systemd` の unit、または `start`／`stop`／`status` のコマンド |

- **2 ノード構成**：2 台だけで動きます。相手が失われた時の自動の引き継ぎには、独立した fencing の装置が必要です。装置が無い場合は、運用者が相手の停止を確かめて手動で切り替えます。
- **補助ノード付き構成**：第 3 のホストで動く補助ノード（`mikagami witness run`）が、どちらが Active かの記録（term と lease）を管理します。補助ノードは fencing の代わりではありません。

検証の状況：

- 補助ノード付き構成は、v0.7.0 の時点で GCE の実機の受入試験を行っています。
- RPM（0.8.0）の build・導入・更新・削除は、Rocky Linux 10.2（aarch64）で試験しています（lifecycle 試験 103 項目すべて PASS。ライセンス文の同梱、`--version`、稼働中の更新・削除の拒否、設定と HA の状態の保全を含む）。
- 2 ノード構成の共通設定・リソースグループ・ヘルスチェックは、Rocky Linux 10.2（aarch64）の 1 台の VM で、実 systemd unit を含むグループ（1 ノード）と、network namespace で分けた 2 ノードの切替を試験しています（[`tests/linux/`](tests/linux/)）。物理的に別の 2 台と実際の fencing の装置での試験は、まだ行っていません。
- Rocky Linux 9 と x86_64 の RPM は、まだ試験していません。

## インストール（RPM）

配布している RPM は Rocky Linux 10（el10）の aarch64 版だけです（[GitHub Releases](https://github.com/hagix9/mikagami-public/releases)。SHA-256 のチェックサムを添えています。RPM の署名はありません）。

```sh
sha256sum -c SHA256SUMS --ignore-missing
dnf install ./mikagami-0.8.0-1.el10.aarch64.rpm
```

x86_64 と Rocky Linux 9 の RPM は配布していません（試験していません）。必要な場合はソースから作ります（[`packaging/rpm/README.md`](packaging/rpm/README.md)）。

- `/usr/bin/mikagami` と `/usr/bin/mkg`、systemd の unit（`mikagami.service`、`mikagami-witness.service`）、HTTP のヘルスチェックの script（`/usr/libexec/mikagami/check-http`）が入ります。
- インストール・更新・削除で、サービスの起動・停止、VIP の移動、HA の状態の削除はしません。HA が動いている間の更新・削除は拒否されます（先に `systemctl stop mikagami` で止めます）。
- RPM の作り方と詳細は [`packaging/rpm/README.md`](packaging/rpm/README.md) と [`docs/rpm.md`](docs/rpm.md) にあります。

## 2 ノード構成の最短セットアップ

両ノードに**同じ**設定ファイルを置き、各ノードで自分のノード ID を 1 回だけ登録します。

1. 両ノードに同じ PSK（共有鍵）を置く（mode 0600、root）。
   ```sh
   umask 077
   head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/mikagami/cluster.psk   # 1 台で作り、もう 1 台へ写す
   ```
2. 両ノードに同じ `/etc/mikagami/mikagami.toml` を置く（下の例。mode 0600、root）。
3. 各ノードで、自分のノード ID を登録する（`/etc/mikagami/node-id` に保存されます。ホスト名からの推測はしません）。
   ```sh
   mikagami node register --config /etc/mikagami/mikagami.toml --node-id node-a   # node-a で
   mikagami node register --config /etc/mikagami/mikagami.toml --node-id node-b   # node-b で
   ```
4. 各ノードで、所有の記録を作る。
   ```sh
   mikagami two-node init --config /etc/mikagami/mikagami.toml
   ```
5. 管理するサービス（例では `nginx.service`）を、OS の起動時に自動で起動しないようにする（`systemctl disable nginx`）。サービスを起動するのは Mikagami だけです。
6. 両ノードで起動する。
   ```sh
   systemctl enable --now mikagami
   ```

## 設定ファイルの例

```toml
[cluster]
id = "example-2n"
topology = "two-node"

[nodes.node-a]
preferred = true                     # 冷起動で先に Active を求める（自動で戻すことはしない）
[nodes.node-a.fencing]               # node-a を止める方法（node-b が使う）
fence  = ["/usr/local/sbin/fence-node", "node-a"]
verify = ["/usr/local/sbin/verify-node-fenced", "node-a"]

[nodes.node-b]
[nodes.node-b.fencing]
fence  = ["/usr/local/sbin/fence-node", "node-b"]
verify = ["/usr/local/sbin/verify-node-fenced", "node-b"]

[two_node]
fencing_device = "independent"       # 独立した fencing の装置がある（無ければ "none"）
fencing_path = "separate"

[[two_node.link]]                    # ノード間の通信路（1〜4 本。2 本を推奨）
segment = "ha-net"
role = "ha"
port = 7946
address = { node-a = "10.0.1.11", node-b = "10.0.1.12" }
interface = { node-a = "eth1", node-b = "eth1" }

[vip]
address = "192.168.100.50/24"
interface = "eth0"

[service]
manager = "systemd"
unit = "nginx.service"

[health]
command = ["/usr/libexec/mikagami/check-http", "http://127.0.0.1/", "--timeout", "2"]

[security]
psk_file = "/etc/mikagami/cluster.psk"

[fencing]
backend = "command"
```

完全な例は [`contrib/examples/`](contrib/examples/) にあります（`two-node-shared.toml`、`two-node-group.toml`、補助ノード付き構成の `node-a.toml`／`node-b.toml`／`witness.toml`）。両ノードの設定が違う時は、両ノードは接続せず、`config mismatch` と表示します。この間、自動の切替はしません。

## 起動・停止・状態の確認

```sh
systemctl start mikagami          # 起動（Standby で始まり、条件がそろうと片方が Active になる）
systemctl stop mikagami           # 停止（Active なら資源を解放し、相手に引き継ぐ）
mikagami two-node status --config /etc/mikagami/mikagami.toml          # 2 ノード構成の状態
mikagami two-node status --config /etc/mikagami/mikagami.toml --json
mikagami status --config /etc/mikagami/mikagami.toml                   # 補助ノード付き構成の状態
journalctl -u mikagami -o cat     # ログ（正常の間は静かで、状態の変化だけが出る）
```

`mkg` は `mikagami` と同じ CLI です（`mkg two-node status ...`）。

## リソースグループ（2 ノード構成）

`[service]` の代わりに `[[group.resource]]` を並べると、書いた順に起動し、逆の順に停止します。

```toml
[[group.resource]]
name = "db"
type = "systemd"
unit = "postgresql.service"

[[group.resource]]
name = "app"
type = "command"
start = ["/usr/local/sbin/app-start"]
stop = ["/usr/local/sbin/app-stop"]
status = ["/usr/local/sbin/app-status"]    # running か stopped だけを出力する

[[group.resource]]
name = "vip"
type = "vip"                                # [vip] のアドレスをこの位置で付ける
```

- 各資源は、起動の後にその状態を確かめてから次へ進みます。全部が起動し、ヘルスチェックが成功してから VIP を公開します。
- 途中で失敗したら、その先は起動せず、全体を逆順に止めます。
- 停止を確かめられない資源があると、そのノードは資源を持っているとみなされ、相手は fencing の確認なしには引き継ぎません。
- 各資源の状態は `mikagami two-node status` に表示されます。

## ヘルスチェック

```toml
[health]
command = ["/usr/libexec/mikagami/check-http", "http://127.0.0.1/healthz", "--status", "200", "--contains", "ok", "--timeout", "2"]
timeout_sec = 5
failure_threshold = 3      # 3 回続けて失敗で異常
success_threshold = 2      # 2 回続けて成功で正常に戻る
on_failure = "warn"        # warn / restart / failover（2 ノード構成）
```

- `command` は任意のコマンドで、終了コード 0 が正常です。HTML の本文や API の応答を調べる時は、同じ形の script を書いて指定します。
- `warn`：ログと状態の表示だけ。
- `restart`：Active のまま、サービスを止めて起動し直す（10 分に `restart_limit` 回まで）。
- `failover`：相手が接続していて健全な Standby の時だけ、自分の資源を解放し、その解放を確かめた後に相手が引き継ぎます。ヘルスチェックの失敗だけで相手を昇格させることはなく、fencing も使いません。解放したノードは 10 分の間、所有を取り戻しません。
- 補助ノード付き構成では `warn` だけです。

## フェイルオーバーと安全上の制約

- 両ノードが同時に Active になることを防ぐことを最優先にします。通信が切れただけでは、相手が止まったとはみなしません。
- 相手が失われた時の自動の引き継ぎは、`[two_node] fencing_device = "independent"` と `[fencing] backend = "command"` があり、fencing の装置で相手の OS の停止を `verify` で確かめた後だけです。fencing の装置は、電源・ハイパーバイザー・クラウドの制御面など、相手の OS の外から OS を止められるものでなければなりません。
- 自動の failback（優先ノードへの自動の戻し）はしません。
- 管理するサービスと VIP を、Mikagami 以外（OS の起動時の自動起動など）から起動してはいけません。
- 補助ノード付き構成では、補助ノードの状態をバックアップや snapshot から戻してはいけません。
- 2 台のバージョンは揃えます。更新は両ノードを止めてから行います。

## 障害時の操作（2 ノード構成）

まず状態を確かめます。

```sh
mikagami two-node status --config /etc/mikagami/mikagami.toml
journalctl -u mikagami -o cat
```

- **相手が失われ、自動で引き継がれない時**（fencing の装置が無い、fencing が失敗した等）：相手の OS が止まっていることを、電源・ハイパーバイザー・クラウドの制御面で運用者が確かめてから、残ったノードで次を実行します。これは運用者の責任での切替です。
  ```sh
  mikagami two-node takeover --config /etc/mikagami/mikagami.toml --attest-peer-stopped node-b
  systemctl kill --kill-whom=main -s USR1 mikagami     # 要求を daemon に処理させる
  ```
  fencing の装置がある場合は `--attest-peer-stopped` の代わりに `--fence node-b` で、装置で止めて確かめてから昇格するよう要求できます。相手と接続している間は、どちらも拒否されます。
- **`config mismatch` と表示される時**：2 台の設定ファイル（または版）が違います。同じファイルにして両方を再起動します。不一致の間は自動の切替をしません。
- **資源の停止を確かめられない時**（status が `blocked`）：そのノードは資源を持っているとみなされ、相手は fencing の確認なしには引き継ぎません。原因の service を確かめて直します。

補助ノード付き構成の操作（`mikagami recover` など）は [`docs/deployment.md`](docs/deployment.md) にあります。

## 補助ノード（Witness）付き構成

2 台のノードと、第 3 のホストの補助ノードで構成します。設定はノードごとのファイル（`contrib/examples/node-a.toml`、`node-b.toml`）と補助ノードの設定（`witness.toml`）です。補助ノードでは `mikagami witness init` で状態を 1 回だけ作り、`mikagami-witness.service` を起動します。手順は [`docs/deployment.md`](docs/deployment.md) にあります。共通設定（`[nodes.<id>]`）、リソースグループ、`on_failure` の `restart`／`failover` は、補助ノード付き構成では使えません（ヘルスチェックは警告のみ）。

## 既知の制約

- 対応する構成は 2 ノード（または 2 ノード + 補助ノード）だけです。グループは 1 つ、資源は 8 個までです。
- 試験の実績は Rocky Linux 10.2（aarch64）の VM までです。Rocky Linux 9、x86_64、物理的に別の 2 台、実際の fencing の装置での試験はまだです。
- 同じノード ID を 2 台で登録すると、2 台は接続できず安全側に止まりますが、「ID の重複」とは表示されません（`mikagami node show` で各ノードの ID を確かめてください）。
- 記録された過去の通信を第三者が再送すると、相手が「設定の違う相手として生きている」と見え、自動の切替が抑えられることがあります（不正な昇格や fencing は起きず、可用性が下がるだけです）。
- ヘルスチェックは daemon の制御のループの中で実行するので、2 ノード構成では `health.timeout_sec` は 30 秒以下です。
- `failover` で解放した後に相手が引き継がなかった場合、サービスは止まったままになりえます（解放したノードは 10 分間、所有を取り戻しません）。
- 主アドレスが `/32` の環境（GCE など）では、VIP も `/32` にする（または VIP を link と別の NIC に置く）必要があります（[`TWO_NODE_ARCHITECTURE.md`](TWO_NODE_ARCHITECTURE.md) §3.3）。
- 共通設定を使う 2 台は、版が混在すると接続しません。どの構成でも、更新は両ノードを止めてから行います（rolling upgrade は未対応）。
- `mikagami status`（汎用の状態表示）はグループの最初の service だけを示します。2 ノード構成では `mikagami two-node status` を使います。

## 詳細なドキュメント

| 文書 | 内容 |
|---|---|
| [`docs/configuration.md`](docs/configuration.md) | 設定の全項目（共通設定、リソースグループ、ヘルスチェックを含む） |
| [`docs/deployment.md`](docs/deployment.md) | 導入と運用（補助ノード付き構成） |
| [`docs/rpm.md`](docs/rpm.md) | RPM の導入・更新・削除と安全の規則 |
| [`TWO_NODE_ARCHITECTURE.md`](TWO_NODE_ARCHITECTURE.md) | 2 ノード構成の設計と動作 |
| [`TWO_NODE_SAFETY_MODEL.md`](TWO_NODE_SAFETY_MODEL.md) | 2 ノード構成の安全モデル |
| [`docs/safety-model.md`](docs/safety-model.md) | 安全モデル（補助ノード付き構成） |
| [`docs/cli-command-names.md`](docs/cli-command-names.md) | `mkg` と `mikagami`、コマンドの一覧 |
| [`tests/linux/README.md`](tests/linux/README.md) | Linux の受入の script |

`docs/` のうち architecture、testing、safety-model、persistence、protocol、state-machine、security、gce-fencing、future は開発者向けの設計・検証の記録で、開発の工程の識別子を含みます。

## ライセンス

Mikagami は [Apache License, Version 2.0](LICENSE) で提供します。バイナリに組み込まれる第三者の Rust クレートは、それぞれのライセンス（MIT、BSD-3-Clause など。いずれも許容型）に従います。一覧は [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md) にあり、RPM は各クレートのライセンス文を `/usr/share/licenses/mikagami/` に入れます。
