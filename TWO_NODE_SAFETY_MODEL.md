# Mikagami 2 ノード構成 — 安全モデル

正典は本書である。実装は `src/two_node/controller.rs` にある。試験は `src/two_node/sim/tests.rs`（シミュレーション）と `src/two_node/runtime/tests.rs`（ループバックの E2E）にある。

## 1. 前提（外部への依存を明示する）

| ID | 前提 | 破られた時 |
|---|---|---|
| A-1 | `fencing_device = "independent"` の fence device は peer の OS の外（電源、hypervisor、cloud の control plane）にあり、OS を停止させる。verify は、その停止をその control plane で観測した時だけ `isolated` を出力し、`MIKAGAMI_FENCE_INCIDENT`（operation ID）と `MIKAGAMI_FENCE_ATTEMPT` で同じ操作に結びつける | 喪失の引き継ぎで二重 Active が起こりうる（試験 `lying_verify_is_an_explicit_assumption…` で明示した）。再接続の時に検出し、古い側が手放す |
| A-2 | 停止させた OS は VIP を持たない（VIP を OS の永続設定に入れない）。管理対象の service は OS の起動時に自動で起動しない（unit を enable しない） | 再起動した旧 Active で資源が残りうる。ただし Mikagami の起動時の cleanup がそれを止める |
| A-3 | Mikagami の外の主体は、Standby の資源を起動しない（既存の `deployment.md` と同じ運用規則） | 検出できない |
| A-4 | operator の attestation（`--attest-peer-stopped`）は、peer の OS の停止を operator が確かめた時だけ出す | 二重 Active が起こりうる（operator の責任） |
| A-5 | peer の link は PSK を知る者だけが認証に通る（PSK が漏れていない） | 偽の announce や grant を受け入れうる |
| A-6 | 共有ストレージ、外部 DB、アプリケーションの内部データの一貫性は保証しない（v0.7 と同じ）。「二重の書き込み」は「管理する service が 2 台で同時に active」という意味で扱う | — |

外部の信頼できる停止確認なしに、任意の分断で安全と可用性を両立できるとは主張しない。fencing の無い構成では、peer を喪失した時の自動引き継ぎをしない（安全を優先し、可用性を譲る）。

## 2. 守る不変条件と実現の仕方

| # | 不変条件 | 実現 |
|---|---|---|
| I-1 | 二重 Active、二重 VIP、二重の書き込み（service）を許さない | 所有（Promoting / Active）を始める根拠を 3 つに限る（§3）。どの根拠も「相手が資源を持たない」ことを示す（生きている相手の Standby とゼロ資源の証言、または相手の OS の停止の観測）。シミュレーションで S-1〜S-6 を常時検査している |
| I-2 | 通信断を fencing の完了の証明にしない | 喪失は incident を開く条件にすぎない。昇格には verify の `isolated` が要る（`promote_from_confirmed`） |
| I-3 | fencing 要求の受理と停止の確認を区別する | fence の action の結果（`ReportedSuccess` など）は incident を `Verifying` に進めるだけである。`Confirmed` にするのは verify の `Isolated` だけ（`on_fence_action` / `on_verify`） |
| I-4 | 不確実な状態では自動昇格しない | SIGUSR1 はその時点での再評価だけを意味し、後まで残らない。verify の結論が出ない、cycle の timeout、記録の保存の失敗、cleanup の未確認、矛盾、記録の破損、peer の状態が不明（未接続）のときは、どれも昇格しない |
| I-5 | 復帰した node は古い所有権で書き込みを再開しない | 起動は常に Demoting から始まり、trusted ZeroResource の後に Standby になる。所有を再開する経路は無い。相手の epoch がより新しければそれを学ぶ |
| I-6 | fencing の再試行には上限を設ける | 1 cycle の action は `max_fence_actions`（1〜3）回まで、verify は `verify_polls` 回まで、cycle は `cycle_timeout_sec` 以内、10 分に 3 cycle まで、operator の要求は 1 process に 10 回まで。`not-isolated` の後は、peer が認証つきで戻るまで自動では fence しない（この印は永続で、再起動をまたいで残る）。所有の資格の無いノードは fence しない（停止させても自分が所有できないため） |
| I-7 | 古い結果や古い epoch を新しい証明に再利用しない | attempt ごとに新しい operation ID を使い、結果は同じ ID の incident にだけ適用する（違えば無視）。incident は基準の epoch と喪失の episode に結びつける。incident は process をまたがない（起動時に破棄）。使った proof は intent と同じ原子的な保存で消費し、履歴に `confirmed-consumed` を残す。operator の attestation は 1 回だけ使える |
| I-8 | 設定変更や再起動で安全制約を迂回できない | 警告は gate を変えない。`fencing_device = "independent"` の宣言は「喪失の引き継ぎを試みてよい」という意味だけで、昇格には runtime の verify が要る。再起動では proof、claim、観測の回数、cycle の予算（process 内）が消え、安全側に戻る。記録を消したり巻き戻したりしても、得られるのは cleanup-only mode か、Standby の状態だけである |
| I-9 | 復帰した node は原則 Standby とする | I-5 と同じ |

## 3. 所有権：Witness が担っていたものを何で置き換えたか

| Witness が担っていたもの | 2 ノード構成での実現 |
|---|---|
| 所有権の決定（term の CAS） | (a) Grant：生きている peer が、自分が Standby で資源ゼロであることを確かめ、grant を永続に記録してから応答する（付与側 1 台につき 1 epoch に 1 回）。(b) Fence：相手の OS の停止を、この process が独立 device で確認する。(c) Operator：人の attestation |
| term | 永続の `epoch`。新しい epoch は、上の根拠のどれかと同時にだけ記録する（`max(知っている epoch)+1`）。epoch そのものは権限ではない |
| lease（期限つきの排他） | 置き換えない。Active は期限なしで継続する。排他は「相手が資源を持たない」証拠で保つ。分断中に旧 Active を止める手段は fencing だけである |
| 古い所有者の排除 | fencing（OS の停止）、または相手の Standby とゼロ資源の証言 |
| 復帰時の照合（SOR） | 起動時の無条件の cleanup と Standby。announce による epoch の学習。矛盾の検出（§6） |

### 3.1 epoch は何を守り、何を守らないか

- 守るもの：fence の incident の基準（epoch が変わった proof は使わない）、grant の一意性（付与側は過去の付与以下の epoch を出さない）、再接続の時の順序づけ（古い側が手放す）、監査の記録。
- 守らないもの：二重 Active の防止そのもの。ローカルの epoch を増やすだけで 2 台の競合が解決するとは仮定しない。所有の開始の根拠（§3 の (a)(b)(c)）が排他を担う。
- 次の 2 つの場合は epoch 番号が再使用されうる。どちらもランダム探索で実際に観測した。
  - 記録が壊れたり失われたりして、epoch の知識が失われた場合。
  - operator の要求（attestation、または fence）による昇格の場合。全面停止の後に単独で復帰したノードでも受け付けるため、peer と一度も接続しないまま、自分の知る epoch に 1 を足すことがある。そのため、自分が停止していた間に peer が取った epoch を知らない。
- 再使用されても同時の所有は起きない（同時の所有の禁止 S-6 は常に成り立つ）。そのため epoch の一意性（S-4）は「記録が無傷で、grant または自動の fence を基点とする昇格の間」の性質として主張する。自動の fence では、この process の中で peer を観測した時に epoch を学んでいる。

### 3.2 起動世代（incarnation）

- process ごとに乱数の UUID を使う（永続化しないので、巻き戻されない）。link の Hello、announce、control message は incarnation に結びつける。
- grant は claimant の incarnation に結びつける。古い incarnation への grant と、別の incarnation から届いた grant は使わない。
- 「peer を連続 2 回観測した」という回数も incarnation ごとに数える。

### 3.3 永続の記録は知識であって権限ではない

記録（`OwnershipState`）が無い、壊れている、別のクラスタやノードのものである、保存に失敗した、のいずれの場合も cleanup-only mode にする。資源を解放し、昇格、claim、fence はしない。

ただし付与（grant）だけはできる。そのノードは自分では所有しないので、grant の記録が無くても自分が所有することを防げるからである。こうして片側の記録が壊れても、もう一方が協調で所有できる（可用性）。

記録を巻き戻しても、得られるのは古い知識だけである。所有の開始には、新しい grant か、この process で確認した fence が必要になる。

## 4. 昇格の gate（実装の順）

### 4.1 Grant（`maybe_claim` → `on_claim` → `on_grant` → `begin_promotion`）

- claimant 側の条件はすべて必要である。Standby、trusted ZeroResource、記録は使える、矛盾なし、停止中でない、実行中の操作なし、incident なし、`holding = false`、未解決の自分の grant なし、資格あり（昇格の失敗が上限未満）、peer は接続中で Standby かつ資源ゼロ、peer の grant / claim なし（競合の時は node id の小さい側だけが続ける）。
- claim は announce に載せてから送る。付与側は、claim を載せた announce を受け取るまで判断を保留する（最大 5 s）。
- 付与側の条件もすべて必要である。Standby、trusted ZeroResource、矛盾なし、実行中の操作なし、incident なし、`holding = false`、未解決の grant なし（同じ claim の再送は冪等）、claim の epoch が自分の epoch と付与の high-water より大きい、claimant の incarnation が現在の peer と一致する。grant を永続に記録してから応答する。
- claimant は 5 s 以内に届いた grant について、条件を再確認する。条件が崩れていれば Abandon を送り、遅れて届いた grant を無視する。

### 4.2 Fence（`maybe_takeover` → `on_fence_action` → `on_verify` → `promote_from_confirmed`）

§4.3 の条件（`TWO_NODE_ARCHITECTURE.md`）に加えて、昇格の直前に次をすべて確かめる。同じ喪失の episode であること、基準の epoch が不変であること、対象が設定の peer であること、operation ID が未使用であること、自分が Standby で trusted ZeroResource であり、矛盾も停止中の状態も無いこと、所有の資格があること。

一つでも欠ければ、確定した proof も使わずに破棄する（`confirmed-unused`）。

### 4.3 共通（`begin_promotion`）

intent（epoch と基点）と `holding = true` を永続に書いてから、資源を取る。書けなければ資源に触れない。

資源は VIP → service → health → GARP の順に取る。どれかが失敗すれば、service の停止 → VIP の解放の順に戻し、昇格の失敗を数える。Active への遷移は、取得がすべて成功し、取得中に矛盾も停止の要求も無かった時だけである。

## 5. 解放（Release）

- 順序は service の停止（trusted Stopped）、次に VIP の解放（trusted Absent）である。両方を確認できた時だけ記録の `holding` と intent を消し、「released」と log に出す（D-1 の教訓：解放を送れていないのに「解放した」と書かない）。
- 確認できなければ Blocked とし、10 s ごとに再試行する。Blocked のノードは資源ゼロを announce しないので、peer は協調では所有しない。

## 6. 矛盾の扱い

- 自分が所有している（Promoting / Active）ときに、peer が所有中で、epoch がより新しいか同じ（peer が自分を owner と主張している）と分かった場合：手放す（Release）。この process では、以後の自動の昇格、claim、grant、fence を止める。
- peer が所有中で epoch がより古い場合：peer が手放すまで待つ（WARN）。
- peer がより新しい epoch を、資源を持ちうる状態で announce した場合：手放す。
- fence を基点にした Active の前に、fence したはずの peer の同じ incarnation が戻ってきた場合：前提 A-1 が破られている（verify が嘘をついた）。古い epoch の側が手放し、新しい epoch の側が唯一の所有者として残る。

## 7. 分断の場合分け（要約）

| 状況 | 結果 |
|---|---|
| 片方のセグメントだけ断 | 他方の link で接続を保つので何もしない（経路の劣化を WARN） |
| 全セグメント断＋独立 fencing（経路は別） | Standby が fence し、停止を確認してから昇格する。旧 Active は停止される |
| 全セグメント断＋fencing の経路も断 | fence が確定しないので昇格しない。旧 Active が提供を続ける |
| 全セグメント断＋fencing なし | 昇格しない（operator の attestation を待つ） |
| 非対称な断 | ACK を要するため、両側で link が down になる。以降は全断と同じ |

## 8. 検査の性質（シミュレーション）

- S-1：VIP は高々 1 台。
- S-2：service は高々 1 台。
- S-3：Active は高々 1 台。
- S-4：epoch の所有者は高々 1 台（記録が無傷で、operator の要求を使わない間）。
- S-5：昇格を始める瞬間、相手は資源を持たない。
- S-6：所有（Promoting / Active）は同時に高々 1 台。

前提 A-1 と A-4 は模型の中で守る（fence device は正直、operator は停止した peer だけを attest する）。A-1 を破った場合の挙動も、別の試験で明示した。

## 9. 共通設定、リソースグループ、ヘルスチェックの追補（2026-11-20）

### 9.1 設定の不一致（共通設定）

- 共通設定（`[nodes.<id>]`）の両ノードは、link の `Hello` に設定の要約（節ごとの digest）を載せる。比較は MAC と identity（cluster、from、to、link）と seq の確認の後だけ。違えば session を作らない。
- 不一致の相手は「生きているが非互換」（`Event::PeerIncompatible(true)`）。§4 の gate に次が加わる：自動の fence（`takeover_base_ready`）、冷起動の claim（`maybe_claim`）、運用者の attest と fence を拒否する。不一致の間は link の喪失を loss episode にしない。不一致が来た時点の loss episode は終わり、open な fence incident は廃棄する（結果は使わない）。不一致が見えなくなっても、それ自体は loss ではない（相手を一度も受け入れていないので、この process の観測から自動の takeover は生じない）。`fence_stopped` は解除しない（解除は認証された実際の復帰だけ）。
- 要約が比べるのは設定ファイルの値だけである。fence・verify・health の script の中身、PSK の中身、バイナリの既定値の違いは比べない（PSK の違いは MAC の失敗、つまり従来どおりの通信断になる）。
- 残余 NB-2（受容済み）：`Hello` は受信側の nonce に結び付いていないので、記録された過去の `Hello` の再送は、相手を「生存・非互換」と見せて自動の takeover を抑止しうる。安全の根拠：`on_incompatible` が行うのは loss episode の終了と open な fence incident の廃棄（durable な記録への retire の追記）だけで、昇格・claim・grant・fence を起こす経路を持たない。`fence_stopped` も解除しない。`Hello` は MAC と identity の確認の後に比べるので、PSK を持たない第三者は新しい内容を作れない。試験：`two_node::sim::tests::a_config_mismatch_*`、`a_mismatch_*`、`operator_takeovers_are_refused_while_*`、`two_node::runtime::tests::loopback_config_mismatch_*`（Linux の S2 でも確認）。影響は可用性の低下（自動の引き継ぎが起きない）だけ。
- 残余 NB-1（受容済み）：同じ ID を両ホストで登録した場合は、接続が成立せず（両方が dial、または bind の失敗）安全側に止まるが、それを ID の重複としては報告しない。安全の根拠：冷起動の昇格は接続中の相手の grant を要し、一度も接続していなければ loss episode は始まらない（自動の fence も無い）。記録は node id に結び付いており、別の ID の記録は読まない。`node register --replace` は記録がある間は拒否する。運用：`mikagami node show` で各ノードの ID を確かめる。

### 9.2 リソースグループ

- 所有の単位はグループ全体で、§5 の解放の規則をグループに広げる：解放は逆順で、ある資源の停止を確かめられなければそこで止め、資源なし（zero-resource）としない。したがって grant（§4.1）を出す clean Standby にならず、相手は fence の確認（§4.2）なしに昇格しない。
- 取得は順に、各資源をそれ自身の観測で確かめ、全部の後に health が成功してから GARP を出す。途中の失敗は取得の失敗（`AcquireResult::Failed`）で、既存どおり全体の解放に進む。

### 9.3 ヘルスチェックの動作（`on_failure`）

- `failover` は §4.1 の grant の経路だけを使う：Active が自分の資源を解放し（確かめた解放だけ）、clean Standby として相手の claim に grant を出した後に、相手は昇格する。相手が接続中・clean Standby・eligible・grant も claim も無い、の全部を満たさない時は何もしない。fence は使わない。
- 解放したノードは 600 秒の間 eligible でない（`cooldown_until`）。相手の側の `failover` はこの間、相手（このノード）が eligible でないので拒否される（往復の防止）。
- `restart` は所有を保ったまま service だけを止めて起動し直す。停止または起動を確かめられない時は、資源の解放（`Event::LocalResourceFailure`）に進み、確かめた解放だけが所有を手放す。この解放の後も 600 秒は eligible でない。
- health の失敗だけでは、loss episode も fence incident も生じない。
- `failover` の gate には、相手が shutdown 中（`leaving`）でないことと、`failover.auto = true`（相手が自動で claim する）であることも含む。lock を失ったノードは health の restart をしない（Acquire・Release と同じく保護された操作）。
- 可用性の残余（安全への影響はない）：
  - 解放の後に相手が切断した、または相手が claim しなかった場合、サービスは止まったままになりうる。相手は通常の冷起動の条件（両者が clean Standby、`bootstrap_dwell_sec`）で claim しうるが、解放したノードは 600 秒の間 claim しない。
  - cooldown は process の memory にだけあり、再起動で解除される。
  - 両ノードで共通の原因により health が失敗し続ける場合は、10 分ごとに引き継ぎが往復しうる。
  - health の実行は制御のループの中で同期的に行う（2 ノード構成では `health.timeout_sec` を 30 秒以下に制限）。その間、SIGTERM の処理や claim への応答が遅れる。restart では、資源ごとの stop・start の timeout が重なりうる。
