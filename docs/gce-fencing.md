# GCE fencing helper and route handoff

> 開発者向けの設計・検証の記録です。開発の工程の識別子（段階や判断の番号）と、公開候補に含まれない内部の資料への参照を含みます。利用の手順は [`README.md`](../README.md) と [`configuration.md`](configuration.md) を参照してください。

- 状態：v0.7 の検証の構成。helper `mikagami-gce-fence` は feature `j25-gce-fence` を付けた時だけ build され、既定の build（`cargo build --release --locked --bin mikagami`）には含まれない。本番への配線は v0.7 の対象外。本番の意味と範囲（D-2）は後の版で決める。
- **本書が G-2 の安全契約（R4.1 と R5）の正典である。** 契約の全文は repo 外の監査の束にあり、場所は `MIKAGAMI_V07_CONTRACT_AMENDMENT.md` §3 に記す。

## 1. 構成

- fencing は汎用の `fencing.backend = "command"` に helper の `fence` / `verify` を指定して使う（[`configuration.md`](configuration.md)）。
- helper の plan の**標準の構成は `combine = "all"`**（GCE の instance の stop と alias IP の剥奪の両方が isolated の時だけ isolated。OD-J25-5）。stop だけでは新 node への alias の割当てが拒否される。`any-sufficient`、stop だけ、alias だけの plan では、昇格（L1）そのものは進むが、route handoff は GCE に書き込まない（G-A3）。
- route handoff は node の設定の `[route]` で有効にする（[`configuration.md`](configuration.md)）。

## 2. 三つの層

| 層 | 状態 | 意味 |
|---|---|---|
| L1 内部の昇格 | `PromotionAttemptResult::Succeeded` | lease、guest の VIP、service、health が揃い、Active になった。**切替の成功とは報告しない** |
| L2 GCE の経路 | 最大で `ROUTE_CONFIRMED` | GCE の alias が自分の NIC にあり、peer の NIC に無いことを観測した。観測の時刻つきで、条件が続く間だけ有効 |
| L3 service への到達 | `SERVICE_REACHABLE` | node の外から VIP の service に接続できた。daemon は確かめない |

HA の切替の最終の成功は L1、L2、L3 と外部の検出器がすべて成り立つことである。daemon は「切替の成功」と書かず、`service route handoff …` の行で RH の状態を出す。

## 3. route handoff（RH）の規則

- RH の記録は term ごとに 1 つの file。消えない属性 `sent` を持ち、daemon は helper の書込みの step を spawn する**直前に** `sent = yes` を durable に書く。書けなければ spawn しない。
- 状態：`NOT_AUTOMATED(bootstrap | operator-attested | no-provenance | disabled)`、`INTENT_RECORDED`、`REQUESTED`、`OBSERVING`、`ROUTE_CONFIRMED`、`ROUTE_PARTIAL`、`ROUTE_LOST`、`ROUTE_FAILED(sent | not-sent)`、`ROUTE_UNKNOWN`、`ABANDONED(lease-lost | demoted | restart | term-changed)`。`Degraded` / `QuorumUnknown` の間は GCE に書き込まない。再起動した node の残った RH は `ABANDONED(restart)` で、書き込まない。
- **GCE への自動の書込みの前提（G-ASSIGN）**：G-A1 昇格が `FencingClearance` の経路で成功した（BA の経路では書き込まない）。G-A2 clearance の由来が backend の attempt token（T5）である（operator の attestation では書き込まない）。G-A3 helper が、同じ `(incident_id, attempt_token)` の stop と alias の両方の fence の記録の `confirmed` を確かめる（plan は stop と alias で `combine = "all"`）。G-A4 送る直前にこの term の Active で lease が使え、control lock が live。G-A5 この term の送った記録が無い。G-A6 実行の予算（§4）を満たす。
- **自動の書込みは term ごとに次の 2 つだけ**（R5）：`route-assign` 1 回と、条件 R-1〜R-9 をすべて満たす時の `route-reissue` 1 回（同じ requestId、同じ body の文字列）。3 回目は無い。新しい観測から body を作り直して送ることは無い。`reissued = true` は spawn の前に durable に書く。
  - R-1 元の記録が `OutcomeUnknown` で、種類が `Timeout`、`Transport`、`ServerError(5xx)`。R-2 再発行の記録が無い。R-3 この term の操作を一度も見ていない。R-4 完全な操作の一覧での不在が `confirm_hold` 以上離れて 2 回以上続く。R-5 元の送信から 20 秒以上、RH の開始から `deadline_sec − 60` 秒より前。R-6 自 NIC の観測が元の body の基と完全に同じで、保護の range が自 NIC に無い。R-7 同じ周の peer の観測が absent。R-8 G-A3、G-A4、予算、lease の残りを spawn の直前に再確認。R-9 再起動の後ではなく、より新しい別の経路の記録が無い。
- **`ROUTE_CONFIRMED` の条件**（同じ観測の周期で、すべて）：C-1 この term の Active で lease が使える。C-2 自 instance の名前と数値の ID が一致し、保護の range がすべて設定の NIC にある。C-3 peer の名前と数値の ID が一致し、保護の range がどの NIC にも無い（describe の失敗、404、ID の不一致では不成立）。C-4 C-2 と C-3 が `confirm_hold_sec` 以上離れた 2 回の観測で続けて成り立つ。C-5'（送った RH だけ）この term の要求の操作（応答で得た名前、または完全な一覧で `clientOperationId` がこの term の requestId と一致する唯一の操作。`targetId` が自 instance、`operationType` が `updateNetworkInterface`）が DONE で error が無い。完全でない一覧は不明として扱い、一致 0 件は送らなかったことの証明にしない。
- 送っていない RH は、C-1〜C-4 の観測だけで `ROUTE_CONFIRMED(not-sent)` にしてよい。
- **自動では禁止**：同じ term の 3 回目の送信、fencing の経路の外の alias の剥奪、部分の割当ての補正や取り消し、route の失敗を理由にした降格や切替、再 fencing、旧 node の start。
- helper の subcommand：`fence`、`verify`、`route-check`（GCE の API を呼ばず、G-A3 の記録だけを読む）、`route-observe --part own|peer|op`（読み取り）、`route-assign`、`route-reissue`、`operator-assign`（operator だけ。peer が TERMINATED で peer の NIC に range が無い時だけ送る）。乱数の requestId で送る bare の `assign` は無い。helper の 1 回の起動で GCE の compute API は高々 1 回。
- 操作の一覧の照合の読み取りは filter（`targetId`）と件数の上限だけで行い、orderBy を併用しない（GCE が拒む）。

## 4. 実行の予算（設定できない）

| 記号 | 値 |
|---|---|
| renew の応答の直後の `time_until_expiry` の上限 | 約 8.0 s（TTL 10 s − safety margin 2 s） |
| renew の timeout | 2.0 s |
| RH の step の execution / return deadline | 2.0 s / 3.0 s |
| step を出してよい lease の残りの下限 | 6.0 s |
| helper の中の token の取得 / API の呼び出しの上限 | 0.5 s / 1.2 s |

RH の step は 1 周の最後の止まる処理として置き、renew の間隔（3 s）ごとに高々 1 つ。上限を超えた書込みは `ROUTE_UNKNOWN` になり、自動の再送は R5 の 1 回だけである。

## 5. 二重の writer

- 違反：(W-1) guest の VIP が 2 台に同時にある、(W-2) service が 2 台で同時に active、(W-3) 保護の range が 2 つの NIC に同時にある。
- guest の VIP の無い node の NIC にある range は writer ではなく、「経路の残り」として可用性の問題に扱う。
- 共有の storage、外部の database、application の内部の data の一貫性は保証しない。
- 二重の writer の防止は、既存の fencing と昇格の gate に頼る。route handoff はそれを弱めず、加える自動の書込みは自分の NIC への range の追加だけである。GCE の range の排他には頼らない。

## 6. operator の判断が要る状態

| RH の状態 | 手順 |
|---|---|
| `sent = no`（`NOT_AUTOMATED(operator-attested)`、`NOT_AUTOMATED(no-provenance)`、`ROUTE_FAILED(not-sent)`） | 旧 node の TERMINATED と、旧 NIC に range が無いことを確かめ、`operator-assign` を 1 回実行する。daemon は観測で `ROUTE_CONFIRMED(not-sent)` に進む |
| `NOT_AUTOMATED(bootstrap)` で range が動いている peer の NIC にある | `operator-assign` は拒む。peer の NIC からの剥奪は operator の手作業による |
| `sent = yes` のすべての状態、`ROUTE_PARTIAL`、`ROUTE_LOST` | 外からの観測で実際の経路を確かめる。この term の daemon は、送った RH の C-5' が成り立たない限り `ROUTE_CONFIRMED` にならない（adopt の command は無い）。直すには `operator-assign` か手動の failover を使う。R5 の再発行の窓の中では operator は経路を操作しない |

## 7. 残余と未検証

- RR-G2-1 daemon は service への到達を確かめない。RR-G2-2 route の失敗の後、新 node は Active のまま通信を受けない（自動の降格や切替はしない）。RR-G2-3 旧 node の遅れた assign が旧 NIC に range を戻すと operator の手作業が要る。RR-G2-4 昇格そのものは operator の attestation（T8）や `combine = "all"` でない plan でも進む（標準の構成で避ける）。RR-G2-5 1 回目の時間切れは照合か 1 回の再発行で戻りうる。再発行も時間切れなら `ROUTE_UNKNOWN`。RR-G2-6 `sent = yes` の後に helper が拒んでも自動では確定しない。RR-G2-7 試験の手段の置き換え。RR-G2-8 確定の後の観測の step で Standby の側の heartbeat の suspect の表示が揺れうる。
- 実機で未検証：peer の describe の失敗（G2-U2）、要求を送った後の outcome unknown（F5-N4）、`route-reissue` の経路（NV-A1）。
