# Mikagami 2 ノード構成（Witness なし）— 構成と設計

- 対象：`cluster.topology = "two-node"`（新設）。既存の Witness 構成（3 ホスト）はそのまま残す。
- 関連：[`TWO_NODE_SAFETY_MODEL.md`](TWO_NODE_SAFETY_MODEL.md)（安全モデル）、[`TWO_NODE_FAILURE_MATRIX.md`](TWO_NODE_FAILURE_MATRIX.md)（故障表）。

## 1. 位置づけ

v0.7.0 では、昇格の権限は第 3 のホストの Witness が出す term / lease（CAS）に依存している。daemon の起動時の Witness session、lease の更新、起動時の照合（SOR）は、どれも具体型の `WitnessSession` を直接使っている（`src/daemon_run.rs` の `connect_witness_session`、`src/linux_node_runtime.rs` の `acquire_lease_once` など）。差し替えのための trait は無い。

そこで 2 ノード構成は、既存の Witness 経路に手を入れず、独立した runtime（`src/two_node/`）として追加した。`daemon run` は設定の `cluster.topology` を見て分岐する。`"two-node"` でなければ（設定の誤りも含めて）従来の経路にそのまま入る（`src/two_node/cli.rs` の `run_daemon`）。

| 部品 | 2 ノード構成での扱い |
|---|---|
| fence / verify の実行 | 既存の `fencing_backend::CommandBackend::run_step` を再利用（有界、process group、pending-reap、実行ファイルの信頼検査） |
| VIP、service、health、GARP | 既存の `ResourceExecutor`（Linux の netlink、systemd、command）を再利用し、昇格と後始末の順序も既存と同じにした |
| PSK、frame | 既存の `Psk`（HMAC を 2 つ追加）と `framing` を再利用 |
| control lock、manual barrier | 既存と同じ規則で、起動時と、保護される副作用の直前ごとに検査する |
| Witness、lease、SOR、BA | 使わない（2 ノード構成には無い） |
| peer の通信 | 凍結済みの Protocol v1 は使わず、変更もしない。2 ノード専用の wire を新設した（magic と HMAC の domain が別） |

## 2. 構成要素

```text
            seg "ha-net" (HA)                       seg "service-net" (service + VIP)
 Node A ───────────────────────── Node B     Node A ───────────────────────── Node B
   │  link 0: 認証つき TCP、heartbeat、ACK       │  link 1: 同じ（独立した経路）
   │
   ├─ controller（純粋な判定核、src/two_node/controller.rs）
   ├─ 永続の所有権の記録（src/two_node/store.rs）
   ├─ fence device（独立：電源 / hypervisor / cloud API）── peer の OS を停止・観測
   └─ 資源（VIP、service）
```

- `config`（`src/two_node/config.rs`）：`[two_node]` と `[[two_node.link]]`、validation、静的な方針（`TwoNodePolicy`）、起動時の警告。
- `store`：永続の所有権の記録（epoch、owner、holding、intent、grant、fence incident、fence の履歴、使用済みの attestation）。
- `wire`：2 ノードの peer message と、接続ごとの session の規則。
- `controller`：時計も I/O も持たない状態機械。昇格の gate はすべてここにある。
- `runtime`：link の thread、fence の実行、資源、operator の要求、状態ファイル。
- `sim`（試験専用）：2 台、2 セグメント、fence device、資源の実体、電源、永続の記録を模型にした決定的シミュレータ。

## 3. 設定

```toml
[cluster]
id = "example-2n"
topology = "two-node"          # 無ければ "witness"（従来どおり）

[node]
id = "node-a"
preferred = true

[peer]
id = "node-b"

[two_node]
fencing_device = "independent" # "independent" | "none"
fencing_path = "separate"      # "separate" | "shared"（independent の時だけ。必須）
# state_path / status_path / operator_dir / max_start_failures は任意

[[two_node.link]]              # 1〜4 本。id の小さい側は peer_address、大きい側は listen
segment = "ha-net"
role = "ha"                    # "ha" | "service" | "combined"（表示用。安全の判断には使わない）
interface = "eth1"
peer_address = "10.0.1.12:7946"

[[two_node.link]]
segment = "service-net"
role = "service"
interface = "eth0"
peer_address = "192.168.100.12:7946"

[fencing]                      # 既存の節をそのまま使う
backend = "command"
fence = ["/usr/local/sbin/fence-peer"]
verify = ["/usr/local/sbin/verify-peer-fenced"]
verify_polls = 60

[failover]
cycle_timeout_sec = 180        # fence_timeout_sec + verify の窓（60 × 2 s）を覆う。短いと起動時に警告
```

- 例：`contrib/examples/two-node-a.toml`、`two-node-b.toml`（2 セグメント＋独立 fencing）、`two-node-single-segment-a.toml`（1 セグメント、fencing なし）。どれも実際の parser を通す試験で検証している。
- 2 ノード構成では `[witness]`、`node.listen`、`peer.address`、`[route]` は存在しない（書くと未知のキーとして拒否する）。Witness 構成の側に `[two_node]` を書いても同様に拒否する。
- `failover.*`（`dwell_sec`、`bootstrap_dwell_sec`、`bootstrap_defer_sec`、`max_fence_actions`、`cycle_timeout_sec`）と `[fencing]` の値域は、既存と同じ validator で検査する。
- 固定の内部値：heartbeat 500 ms、link の timeout 3 s、verify の間隔 2 s、claim の timeout 5 s、自動 fencing の前の最小の稼働時間 30 s、自動の fence cycle は 10 分に 3 回まで、計画停止での引き継ぎの猶予 15 s。

### 3.1 経路の冗長性と fencing の安全性を分けて評価する

| 評価 | 入力 | 用途 |
|---|---|---|
| 経路の冗長性（可用性） | 異なる `segment` の数と、異なる `interface` の数（別々に数える） | 警告。1 本の経路の喪失では fence しない |
| fencing の能力（安全） | `fencing_device`、`[fencing]` | 喪失した peer を自動で引き継げるか |

- セグメントの数を理由に設定を拒否しない。1 セグメントも正式に受け付ける。
- 2 つのセグメントが同じ NIC にある場合（VLAN など）は、「セグメントは 2 つ、NIC は単一障害点」として別の警告を出す。物理 NIC の数とセグメントの数を混同しない。
- 警告は通知にすぎない。警告を受け入れても runtime の gate（昇格の前の fencing の完了確認）は省略されない。

### 3.2 方針の表

| 構成 | 協調の起動・計画停止での引き継ぎ（peer 接続中） | peer の喪失の自動引き継ぎ | operator の手動 failover |
|---|---|---|---|
| 2 セグメント＋独立 fencing（推奨） | 自動 | 確定した fence の後だけ | attest または fence を要求 |
| 1 セグメント＋独立 fencing（経路は別） | 自動 | 確定した fence の後だけ（経路の単一障害点を警告） | 同上 |
| 1 セグメント＋独立 fencing（経路は共有） | 自動 | セグメントの障害では fence も届かないので起きない（安全側） | 同上 |
| 1 / 2 セグメント、独立 fencing なし | 自動 | しない | attest だけ |

`failover.auto = false` の場合、自動の要求は出さない（SIGUSR1 と operator の要求だけ）。

### 3.3 適用の制限：VIP の prefix と link の送信元

- two-node の外向きの link（`peer_address` の側）は、送信元のアドレスを bind しない。送信元はカーネルの経路の選択による。
- 次の条件がそろうと、VIP を付けた時点で、peer 宛ての通信の送信元が VIP になる。
  - link の interface の主アドレスが `/32` である（GCE などの cloud の guest の既定）。
  - VIP が同じ interface にあり、その prefix が peer のアドレスを含む（例：`/24`）。
  - このとき、VIP の接続経路がその subnet の唯一の経路になり、送信元に VIP が選ばれる。
- 網が VIP を送信元とする通信を届けなければ（GCE は VM に割り当てていないアドレスからの送信を届けない）、Active の側のその link は黙って使えなくなる。
- 安全への影響は無い。link の喪失は fencing の証明にならず、両方の link を失えば fence の確認の後でだけ昇格する。
- 可用性への影響はある。経路の冗長が失われ、残りの 1 本の断で不要な fence が起きうる。
- **制限**：主アドレスが `/32` の環境では、VIP を `/32` にする（または VIP を link と別の interface に置く）。主アドレスが subnet の prefix を持つ通常の L2 網では、VIP は二次のアドレスになり、送信元は主アドレスのままなので、この制限は要らない。
- 検知：`two-node status` の `links[].up` で、Active の側の link が落ちたことが見える。
- この制限つきで運用する。製品の修正の案（外向きの link が、その interface の VIP 以外のアドレスを送信元として bind する）は、将来の工程の候補として残す。

## 4. 動作

### 4.1 起動

1. 永続の記録を読む。無い、壊れている、別のクラスタやノードのものである場合は cleanup-only mode にする（資源を解放する。昇格、claim、fence はしない。付与（grant）だけはできる。§5.6 を参照）。
2. 前の process の fence incident は破棄する（`retired-restart`）。fence の結果は、それを出した process の中でしか使わない。
3. 役割は必ず Demoting で始め、service の停止と VIP の不在を確認（trusted ZeroResource）してから Standby にする。記録が自分を owner としていても再開しない。
4. peer と認証つきで接続できるまで、自動では何もしない（Pacemaker の `wait_for_all` に相当）。

### 4.2 協調の起動（grant）

両者が接続していて、両者が Standby で資源ゼロのとき、preferred の側が `bootstrap_dwell_sec` の後に（もう一方は `bootstrap_defer_sec` だけ遅れて）`Claim{epoch = max(両者の epoch)+1}` を送る。claim は先に announce に載せてから送る。

相手は自分が Standby で資源ゼロであること、claim が announce に載っていること、epoch が自分の知る epoch と過去に付与した epoch より大きいことを確かめる。そのうえで grant を**永続に書いてから** `Grant` を返す。claimant は grant を受け取ると、intent（基点は Grant）を永続に書いてから資源を取る。claim が競合した場合は、node id の小さい側が残る。

### 4.3 喪失した peer の引き継ぎ（fence）

条件はすべて必要である。

- 全 link が `dwell_sec` 以上 down（1 本の経路の喪失では起きない）。
- この process が peer を連続 2 回以上「資源を持ちうる」と観測した、または自分が peer に出した grant が未解決。
- 独立した fence device がある（`fencing_device = "independent"`）。
- 稼働して 30 s 以上。fence cycle の予算が残っている。`not-isolated` の後ではない（永続の印）。自分に所有の資格がある。

この条件で incident を開く。incident には新しい operation ID（UUIDv4）、対象、基準の epoch、peer の incarnation を記録する。

fence の action の結果は受理の報告にすぎない。verify が同じ operation について `isolated` を返し、epoch が不変で、同じ喪失の episode が続いている（peer が一度も戻っていない）ときだけ、epoch を 1 つ上げる。その書き込みは、incident の消費と intent（基点は Fence）を 1 回の原子的な保存で行う。その後に資源を取る。

### 4.4 計画停止と引き継ぎ

SIGTERM を受けた Active は、service の停止、VIP の解放、記録の順に処理する。その後、接続中の peer がいれば最大 15 s、`leaving` を announce しながら付与側として残る。peer は即座に claim できる。

### 4.5 operator

- `mikagami two-node takeover --config … --attest-peer-stopped NODE`：peer の OS の停止を operator が保証する手動 failover。1 回だけ使える。peer が接続中なら拒否する。全面停止の後に単独で復帰したノード（この process で peer と一度も接続していない）でも受け付ける。
- `mikagami two-node takeover --config … --fence NODE`：独立 fencing がある時だけ、fence と verify を経て昇格する。
- 要求ファイルを置いた後、daemon に SIGUSR1 を送る。要求ファイルが無い SIGUSR1 は「すべての gate を今すぐ再評価する」という意味だけを持つ（dwell の待ちを省くだけ）。
- `mikagami two-node init` / `status`。状態ファイル（既定 `/run/mikagami/two-node-status.json`）には、daemon の今の役割、epoch、link ごとの up/down を出す（v0.7.0 の `status` が役割を出さない点への対処）。

## 5. Pacemaker から取り込んだもの・取り込まなかったもの

公式資料：Pacemaker Explained（fencing、cluster options、resources、operations の各章）、Clusters from Scratch（fencing）、corosync votequorum(5)。

| 考え方 | 取り込み方 |
|---|---|
| STONITH（fencing 前に資源を回復しない） | fence の確認（verify）の後にだけ昇格する。受理と停止を区別する |
| two_node と wait_for_all | 起動後、peer と一度接続するまで自動では動かない。単独で起動したノードは昇格しない |
| fence race / death match、`pcmk_delay_*` | Active は fence しない。fence するのは、peer を所有しうると観測した Standby だけ。死の応酬はこの規則で防ぎ、遅延による調停は不要にした |
| `stonith-max-attempts`、`stonith-timeout` | `max_fence_actions`（1〜3）、verify の poll の上限、cycle の timeout、10 分に 3 cycle |
| fencing history | 記録の `history`（有界の 64 件）に、operation ID ごとの結果を残す |
| ordering（start / stop の順） | 昇格は VIP → service → health → GARP、後始末は service の停止 → VIP の解放（既存と同じ） |
| monitor / `migration-threshold` / fail count | 昇格の失敗を数え、`max_start_failures` に達したら所有の資格を下ろす（再起動まで）。Active の間の health の失敗は既存の v1.0 D-5 に合わせ、昇格の根拠にも降格の理由にもしない |
| `resource-stickiness` | failback しない。peer が Active の間は claim しない |
| operator intervention | 矛盾、cleanup の失敗、記録の破損では自動の動作を止め、operator に委ねる |
| stop の失敗での fence（`on-fail=fence`） | 取り込まなかった（生きている peer を自動では fence しない）。Blocked の peer は operator が扱う（残余リスク R-6） |
| `startup-fencing` | 取り込まなかった（再起動の直後の推測による fence はしない） |
| quorum device / 第 3 の投票 | 対象外（常設の Witness を要らなくすることが目的） |

## 6. 既存の構成への影響

- `cluster.topology` が無い設定は、従来とまったく同じ shape（`RawConfig`）で解析する。Witness 構成の parse、validation、エラーの種類（`[witness]` が無ければ Parse エラー）は変わらない。
- 変更した既存ファイルは次のとおり。`src/config.rs`（topology の判定、2 ノードの shape、共通の補助関数の切り出し）、`src/security.rs`（HMAC の補助関数を 2 つ追加）、`src/main.rs` と `src/cli.rs`（`two-node` の subcommand と `daemon run` の分岐）、`tests/architecture.rs`（2 ノード構成の guard を 2 つ追加：controller の純粋性と、Witness 構成からの分離。既存の guard は無変更）、`docs/configuration.md` と `docs/architecture.md`（入口を追記）。いずれも Witness 経路の挙動を変えない。
- Protocol v1、Node / Witness の永続の形式、Witness の実装には変更が無い。
