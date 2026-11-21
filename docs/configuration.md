# Configuration

設定形式はTOMLである。ノードの設定は1ファイル（既定の配置先は`/etc/mikagami/mikagami.toml`）、Witnessの設定は別ファイル（`/etc/mikagami/witness.toml`）に置く。未知のキーは**すべて拒否**される（`deny_unknown_fields`）。v1.0より前の設定にあった`cluster.mode`、`cluster.heartbeat_port`、`node.priority`、`node.bind_address`、`peer.priority`、`[heartbeat]`、`[lease]`、`[hooks]`、`[logging]`、`[timeouts]`、`health.interval_sec`、`security.require_*`、`witness.enabled`等は存在せず、書くとエラーになる（値は内部で導出される定数で、設定項目ではない）。

動作確認済みの例は`contrib/examples/`にある（実パーサを通るテストで検証されている）。

## ノード設定

| キー | 必須 | 既定 | 意味 |
|---|---|---|---|
| `cluster.id` | 必須 | | 2ノードとWitnessで共通のクラスタ識別子 |
| `node.id` | 必須 | | このノード。空白・制御文字不可 |
| `node.preferred` | 任意 | `false` | ペアのうち**1台だけ**`true`にする。冷起動で先に要求を出すだけで、安全性の根拠にはならない（failbackもしない） |
| `node.listen` | 条件付き | | `ip:port`。**idが大きい側（Inbound）では必須、小さい側では指定不可** |
| `peer.id` | 必須 | | 相手ノード |
| `peer.address` | 条件付き | | `ip:port`。**idが小さい側（Outbound）では必須、大きい側では指定不可** |
| `witness.id` / `witness.address` | 必須 | | Witnessは必須（Witnessなしの自動昇格はない） |
| `vip.address` | 必須 | | CIDR（例 `192.168.100.50/24`） |
| `vip.interface` | 必須 | | |
| `vip.arp_count` | 任意 | 3 | |
| `service.manager` | 必須 | | `systemd`または`command` |
| `service.unit` | systemd | | |
| `service.start` / `service.stop` / `service.status` | command | | argv配列（絶対パス、シェル非経由） |
| `service.start_timeout_sec` / `stop_timeout_sec` | 任意 | 30 | 1〜86400秒。範囲外は設定エラー（丸めない）。`systemd`では1回のコマンド実行の待機は、この時間に最大2秒の回収予算（`KILL`後のreap確認）を加えた範囲に収まる（`src/systemd_service.rs`の冒頭を参照。spawn自体とD状態の子はこの保証の外） |
| `health.command` | 必須 | | argv配列（絶対パス） |
| `health.timeout_sec` | 任意 | 2 | 1〜86400秒。範囲外は設定エラー（丸めない） |
| `health.failure_threshold` | 任意 | 3 | この回数連続で失敗して初めてunhealthyと報告し、1回だけWARNを出す |
| `health.success_threshold` | 任意 | 2 | この回数連続で成功して初めて復帰と報告し、1回だけINFOを出す |
| `security.psk_file` | 必須 | | 絶対パス。PSKの内容は設定にも引数にもログにも出ない |
| `state.path` | 任意 | `/var/lib/mikagami/state.toml` | 絶対パス |

導出される値（設定項目ではない）: HELLO優先度（preferred=100、他=50。両ノードが同じ値を主張すると接続が拒否される）、heartbeat間隔1秒・unreachable 10秒、lease TTL 10秒・更新3秒、`cluster.mode`は常に`conservative`。

### `[service] manager = "command"`

`start`/`stop`/`status`は**root所有・group/other書込不可・シンボリックリンクでない**絶対パスの実行ファイルでなければならない（親ディレクトリも検査される）。環境変数は消去され（固定の`PATH`と`LANG=C`、`MIKAGAMI_SERVICE_ACTION`のみ）、標準入力は`/dev/null`、出力は4 KiBで打ち切られ、独立したプロセスグループで実行し、期限で`TERM`、2秒後に`KILL`する。リーダーの終了後は、そのグループに残った子を、リーダーを回収する前（グループIDが再利用されない間）に`KILL`し、回収後にグループが空であることをシグナル0で確認する。`KILL`を送れない／グループが空と確認できない場合、その実行は結果なし（`status`は不明、`start`/`stop`は成功としない）で、清掃の責任をMikagamiが保持し、解消するまで以後のコマンドを起動しない。`status`は終了コード0で標準出力が**ちょうど** `running` か `stopped`（末尾の改行は可）のときだけ有効で、それ以外は「不明」として扱われ、Standbyの資源ゼロとは認められない。`start`が成功した後は、自分の`stop`が成功するまで`stopped`を信じない。

**`SIGCHLD`の状態**: このプロセスが自分の子の終了を`wait`で受け取れることが前提である。`SIGCHLD`が`SIG_IGN`（起動元から継承され得る）または`SA_NOCLDWAIT`だとカーネルが子の終了状態を捨て、すべての実行が「リーダー喪失」になって`command`は恒久的に使えない。ハンドラ関数が設定されている場合も、子に触れないことを確認できないため受け付けない。そのためMikagamiは`SIGCHLD`の状態を**読むだけ**で（変更しない）、`manager = "command"`のバックエンドの構築時（拒否されるとデーモンは起動しない）と各コマンドの起動直前に検査し、既定（`SIG_DFL`）以外は理由を明示して拒否する（コマンドは起動されない）。`systemd`マネージャでは起動時の拒否はしないが、`SIGCHLD`が無視されていると子の終了状態が得られず、観測は常に不明（安全側）になる。既定のまま起動すること（子が`ECHILD`となった場合、その子の責任は解消されるがシグナルは送らず、その実行の結果は不確実のままである）。起動元が`SIGCHLD`を無視する設定になっている場合（例: 一部のシェルの`trap '' CHLD`やプロセススーパーバイザ）は、既定に戻して起動すること。`SIGCHLD`の状態はプロセス全体で共有されるため検査は時点のスナップショットであり、起動後にプロセス内の他のコードが変更することは防げない（運用契約: 起動後に変更しない）。検査後に変更された場合、子が回収済みになり、実行は「リーダー喪失」（シグナルを送らない・結果なし・清掃責任を保持）として失敗側に倒れ、次の実行は検査で拒否される。

**`SIGCHLD`拒否の範囲**: 拒否が禁止するのは**新しい子プロセスの起動だけ**であり、すでに負っている清掃責任は消えない。`Runner::run`は最初に未完了の清掃（`clear_pending`）を試み、その後で`SIGCHLD`を検査する（この順序は変更しない。検査の後ろへ移すと責任が回収されなくなる）。この清掃は他の経路と同じ所有権規則に従う: シグナルは保留中のグループにだけ、リーダーが回収されていない（pidが固定されている）と観測された間だけ送り、固定を失った後（`ECHILD`）は旧グループIDに一切送らず、グループが空と認めるのは`ESRCH`だけである。清掃を終えられない場合は`PendingBlocked`（新規起動なし・責任保持）で、`SIGCHLD`の状態によらない。清掃が済んだ後に状態が拒否対象なら`SigchldRefused`で、起動もシグナルもない。したがって「拒否時はシグナルを送らない」は**新規の子とすでに負っている清掃の対象外のプロセスに対して**の意味であり、呼び出し全体がシグナルゼロという意味ではない。この裁定は外部reaperが存在しないという前提（上記）を緩めない。

### `[failover]`

| キー | 既定 | 意味 |
|---|---|---|
| `auto` | `true` | 自動トリガーの有効化 |
| `dwell_sec` | 10 | peer喪失の継続時間（自動fenceの待機） |
| `bootstrap_dwell_sec` | 20 | 冷起動で試みるまでの連続成立時間 |
| `bootstrap_defer_sec` | 15 | preferredでないノードの追加待機 |
| `max_fence_actions` | 2（1〜3） | 1エピソードあたりのfence実行回数 |
| `cycle_timeout_sec` | 120 | 自動サイクルの上限時間 |

自動トリガーは**昇格要求を出すだけ**で、要求は手動のSIGUSR1と同じ単一の試行経路に入り、全gateを毎回再評価する。

- **peer喪失（fence経路）**: `fencing.backend = "command"` かつ、このプロセスがpeerを`Active`として連続2回以上観測した後に失った場合に限る。起動後30秒未満では動かない。再起動直後に「peerが落ちているはず」と推測してfenceすることはない。
- **冷起動（Bootstrap Admission）**: peerが健全で`Standby`のときだけ。fenceは実行せず、fence予算を使わない。
- どちらも、`FAILED`（peerが隔離されていない）になれば**再fenceせず停止**し、peerが復帰するか運用者が介入するまで再開しない。10分間に3サイクルまで。再起動をまたぐ厳密な回数上限は保証されない。

### `[fencing]`

任意。`backend = "none"`（既定）では自動切替は無効で、起動時に1度だけWARNを出す。`backend = "command"`では`fence`と`verify`をargv配列で指定する。`fence_timeout_sec`（既定30）、`verify_timeout_sec`（既定10）、`verify_polls`（既定10）。`fence`は**冪等**（「peerを隔離状態にする」）であること。電源のトグルは不可。`fence_timeout_sec + verify_timeout_sec`は`failover.cycle_timeout_sec`に収まる必要がある。

### `[route]`（v0.7。GCEの経路の引き継ぎ）

任意。`[route]`があるとき、昇格の後にGCEのaliasの経路を自分のNICに移すroute handoffを行う（[`gce-fencing.md`](gce-fencing.md)）。未知のキーは拒否される。

| キー | 既定 | 意味 |
|---|---|---|
| `helper` | — | helperの実行ファイル（絶対path。起動時に`[fencing]`のcommandと同じ信頼の検査） |
| `helper_config` | — | helper自身の設定ファイル（絶対path。`--config`で渡す） |
| `intent_dir` | — | helperと共有するroute handoffのdirectory（このuserの所有、mode 0700） |
| `confirm_hold_sec` | 30（1〜600） | 確定に要る、最初の観測と確認の観測の間の最小の時間（C-4） |
| `deadline_sec` | 300（30〜3600、`confirm_hold_sec`以上） | これを過ぎて確定しない時は`ROUTE_UNKNOWN`と表示する（書込みは続けない） |

route handoffのstepの時間の予算は設定できない。

## Witness設定

```toml
cluster = "example-ha"
id = "witness-1"
listen = "192.168.100.13:7947"
nodes = ["node-a", "node-b"]
preferred = "node-a"
psk_file = "/etc/mikagami/cluster.psk"
state_dir = "/var/lib/mikagami-witness"
on_reboot = "rearm"          # または "refuse"
# max_connections = 16
# rearm_max_downtime_sec = 3600
```

`on_reboot = "rearm"`（既定。v0.7でも維持）では、ホスト再起動後に有効なleaseが残っていれば自動で再武装する。`refuse`は補助策で、状態の巻き戻しを検出する手段ではない（[`deployment.md`](deployment.md)の「Witnessの状態の取り扱い」）。再起動を検知するのは起動識別子（boot id）の変化で、`refuse`にするか、状態ファイルが`rearm_max_downtime_sec`より古い場合は`mikagami witness rearm`を運用者が実行するまで起動しない。バックアップから復元した状態は検出できない（[`persistence.md`](persistence.md)）。

## 起動時の検査

- 未知のキー、`node.listen`/`peer.address`の方向違反、`node.id == peer.id`、相対パスのPSK/状態ファイル、空のargv、制御文字を含むargv要素は起動前に拒否される。
- `failover.auto = true` かつ `fencing.backend != "command"` は拒否ではなく、起動時に1度だけWARNを出す。

## 2 ノード構成（`cluster.topology = "two-node"`）

`cluster.topology` が無い設定は、上の Witness 構成として解析する（従来と同じ）。`"two-node"` の場合は、Witness を使わない別の shape になる。`[witness]`、`node.listen`、`peer.address`、`[route]` は存在せず、peer の経路は `[[two_node.link]]`（1〜4 本）で指定する。`[two_node]` には `fencing_device`（`"independent"` / `"none"`）と `fencing_path`（`"separate"` / `"shared"`）を書く。

設計、方針の表、安全モデルは [`TWO_NODE_ARCHITECTURE.md`](../TWO_NODE_ARCHITECTURE.md) と [`TWO_NODE_SAFETY_MODEL.md`](../TWO_NODE_SAFETY_MODEL.md) にある。例は `contrib/examples/two-node-*.toml` にある。

### 2 ノード共通設定（`[nodes.<id>]`）

2 台に**同じ** `mikagami.toml` を置き、各ホストで 1 回だけノード ID を登録する形式。例は `contrib/examples/two-node-shared.toml`。

```sh
# node-a で
mikagami node register --config /etc/mikagami/mikagami.toml --node-id node-a
# node-b で
mikagami node register --config /etc/mikagami/mikagami.toml --node-id node-b
mikagami node show --config /etc/mikagami/mikagami.toml   # 確認（読み取りのみ）
```

- 登録は設定ファイルと同じディレクトリの `node-id`（mode 0600）に、`cluster.id` と node id を書く。ホスト名からの推測はしない。以後の起動では ID を指定しない。`node-id` は他方のノードに写さない。
- `node-id` が無い（未登録）、`cluster.id` が違う、ID が `[nodes]` に無い、所有者が違う、group/other が書き込める、symlink である、のいずれかでは、全てのコマンドと daemon が設定を拒否する。
- 登録の変更は `--replace` が要り、2 ノードの記録（`two_node.state_path`）が存在する間は拒否する（記録は旧 ID のもの。退避してから行う）。既存の記録が別のノードや cluster のものなら、新規の登録も拒否する。記録は node id と cluster id に結び付いており、別の ID で読み込まれることはない。

| キー | 意味 |
|---|---|
| `nodes.<id>` | ちょうど 2 つ。ID は空白・制御文字不可 |
| `nodes.<id>.preferred` | ちょうど 1 つが `true`。意味は従来の `node.preferred` と同じ（冷起動で先に要求を出すだけ。failback しない） |
| `nodes.<id>.vip_interface` | 任意。そのノードの VIP の NIC 名が `[vip] interface` と違う時だけ |
| `nodes.<id>.fencing.fence` / `.verify` | 「このノードを止める方法」（argv 配列）。相手のノードが使う。`[fencing] backend = "command"` の時は両ノードに必須 |
| `two_node.link[].port` | その link の port（両ノード共通） |
| `two_node.link[].address` | `{ <id> = "IPv4", <id> = "IPv4" }`。両ノード必須、同じ値は不可。id の小さいノードが相手の `address:port` へ接続し、大きいノードが自分の `address:port` で待ち受ける |
| `two_node.link[].interface` | `{ <id> = "NIC", <id> = "NIC" }`。両ノード必須 |
| `[fencing]` | `backend` と時間（`fence_timeout_sec`、`verify_timeout_sec`、`verify_polls`）だけを書く。`fence`／`verify` は書けない（`nodes.<id>.fencing` に書く） |

その他の節（`[vip]`、`[service]`、`[health]`、`[security]`、`[failover]`、`[two_node]` の `fencing_device` など）は従来の 2 ノード設定と同じ。共通設定は各ノードの従来の形に変換され、従来と同じ検証を通る。PSK は `security.psk_file` の別ファイル、HA の状態は `/var/lib/mikagami` のままで、共通の TOML には入らない。

**設定の不一致の検出：** 両ノードは接続の最初に、共通設定の要約（`cluster`、`nodes`、`two_node`（状態の path を除く）、`vip`、`service`、`health`、`failover`、`fencing` の節ごとの digest）を交換する。違う時は相手を受け入れず、status（`mikagami two-node status`）とログに `config mismatch` と違う節の名前を出す。その間、相手は「生きているが非互換」として扱い、**通信断（peer の喪失）とは見なさない**：自動の fence・takeover・冷起動の昇格を始めず、運用者の takeover（`--attest-peer-stopped`、`--fence`）も拒否する。Active のノードは資源を持ったまま、Standby は Standby のまま。不一致が見えなくなっても、それを根拠に自動の takeover はしない（相手を一度も受け入れていないため）。設定を揃えて再起動すると通常どおり接続する。

- 共通設定のノードと従来の形（ノードごとの設定）のノードは接続しない（不一致として扱う）。共通設定の `Hello` は前の版のバイナリには読めないので、前の版のノードとは接続できない。両ノードを止めて同時に更新する（[`deployment.md`](deployment.md)の「アップグレード」）。従来の形の設定どうしは前の版と互換のまま。
- `Hello` は PSK で認証された後に比べる。PSK を知らない第三者は不一致を装えない。記録された過去の `Hello` の再送は、相手を「生存」と誤認させうるが、その結果は自動の昇格をしない方向（可用性の低下）だけである。
- 同じノード ID を 2 台で登録すると、2 台は接続できず安全側に止まるが、「ID の重複」とは表示しない。登録の後に `mikagami node show` で各ノードの ID を確かめる。

### リソースグループ（`[[group.resource]]`、2 ノード構成のみ）

複数の資源を 1 つのグループとして、指定の順に起動し、逆の順に停止する。`[service]` の代わりに書く（併記は不可）。所有と切替の単位はグループ全体（グループは 1 つ）。例は `contrib/examples/two-node-group.toml`。Witness 構成では使えない（単一の `[service]` のまま）。

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
status = ["/usr/local/sbin/app-status"]   # 標準出力がちょうど running か stopped

[[group.resource]]
name = "vip"
type = "vip"          # [vip] のアドレスをこの位置で付ける
```

| キー | 意味 |
|---|---|
| `name` | グループ内で一意。英数字と `-` `_` `.` |
| `type` | `systemd`（`unit`）、`command`（`start`／`stop`／`status`）、`vip`（他のキーなし） |
| `start_timeout_sec` / `stop_timeout_sec` | 任意、既定 30。`systemd`／`command` のみ |

- 資源は 1〜8 個。`vip` はちょうど 1 つ、`systemd`／`command` は 1 つ以上。各資源には `[service]` と同じ規則（絶対パス、root 所有の実行ファイル、`status` の厳密な出力、`systemd` で start/stop/status を書かない等）が掛かる。
- **起動：** 定義の順に起動し、各資源をそれ自身の観測（systemd の状態、`status` の出力、VIP の有無）で確かめてから次へ進む。全部の後に `[health] command` が成功して初めて GARP で VIP を公開する。途中で失敗したら、その先は起動せず、全体を逆順に停止して所有を手放す（`two_node.max_start_failures` で数える）。
- **停止：** 逆の順。ある資源の停止を確かめられない時はそこで止め、それより前（先に起動した資源）は止めない。その場合は資源が残っているとみなし、所有を手放さない（相手は fence の確認なしに昇格しない）。既存の単一 service で停止を確かめられない時と同じ扱い。
- **VIP の位置：** 最後に置くと、VIP は全ての service の起動後に付き、停止では最初に外れる。VIP に bind する service がある時は、その前に置く。どの位置でも、GARP（公開）は health の成功の後である。
- **Standby の確認：** 起動時と降格時の解放は、全資源の停止と VIP の不在を確かめた時だけ「資源なし」とする。
- **状態の確認：** `mikagami two-node status` が、最後の起動・停止で観測した各資源の状態（`running`／`stopped`／`present`／`absent`／`unknown`）を起動の順に示す。表示のための新たな操作はしない。
- `[[group.resource]]` は共通設定の要約の `group` 節に入る（両ノードで違えば不一致として接続しない）。

### ヘルスチェックの動作（`[health] on_failure`）

`[health] command` は、Active のノードで約 2 秒ごとに実行する（2 ノード構成）。終了コード 0 が正常、それ以外と時間切れは異常。`failure_threshold` 回続けて異常で初めて unhealthy、`success_threshold` 回続けて正常で初めて healthy に戻る（既存のキー）。状態は `mikagami two-node status` に出る（安定した状態、連続の失敗・成功の回数、`on_failure`、時間窓の中の再起動の回数、最後の動作）。Witness 構成は従来どおり、警告のログだけである。

| キー | 既定 | 意味 |
|---|---|---|
| `on_failure` | `"warn"` | `warn`／`restart`／`failover`。Witness 構成は `warn` のみ |
| `restart_limit` | 2（1〜10） | `restart` で許す再起動の回数（600 秒の時間窓あたり） |
| `timeout_sec` | 2 | 1 回の health の時間切れ。2 ノード構成では 30 秒以下（health は daemon の制御のループの中で実行する） |

- **`warn`**：ログ（unhealthy になった時と回復した時に 1 回ずつ）と status だけ。
- **`restart`**：unhealthy になったら、Active のまま service を止めて（グループは逆順、VIP は付けたまま）起動し直し（順に）、health を確かめる。上限に達したら `warn` と同じになる。停止または起動を確かめられない時は、資源を解放する（停止を確かめた解放だけが所有を手放す。確かめられなければ Blocked で所有を保つ）。解放したノードは 600 秒の間、所有の資格を持たない（同じノードがすぐ取り戻さない）。
- **`failover`**：unhealthy になったら、**相手が接続中で、資源の無い Standby で、所有の資格があり、grant や claim が残っておらず、shutdown 中でなく、`failover.auto = true` の時に限り**、自分の資源を解放する。相手は、この解放が確かめられてこのノードが grant を出した後にだけ昇格する（health の失敗だけで相手を昇格させない。fence は使わない）。条件を満たさない時は `warn` と同じで、unhealthy の間は 30 秒ごとに再び試す。解放を確かめられない時は Blocked で所有を保ち、相手は引き継がない。解放したノードは 600 秒の間、所有の資格を持たないので、相手の側でも unhealthy になって戻そうとしても、この間は拒否される（往復の防止）。

**HTTP の確認：** `contrib/health/check-http`（curl を使う script）を使える。URL、期待する status（既定 200）、本文に含むべき文字列（`--contains`、固定の文字列）、timeout を引数で取る。

```toml
[health]
command = ["/usr/libexec/mikagami/check-http", "http://127.0.0.1/healthz", "--status", "200", "--contains", "ok", "--timeout", "2"]
timeout_sec = 5
failure_threshold = 3
success_threshold = 2
on_failure = "failover"
```

HTML の本文や API の応答をさらに調べる時は、同じ形（正常の時だけ終了コード 0）の script を書いて `command` に指定する。`command` の実行ファイルは root 所有でなければならない（`[service] manager = "command"` と同じ検査）。health の実行は daemon の制御のループの中で行うので、`timeout_sec` は短く（数秒）する。
