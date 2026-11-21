# Testing

> 開発者向けの設計・検証の記録です。開発の工程の識別子（段階や判断の番号）と、公開候補に含まれない内部の資料への参照を含みます。利用の手順は [`README.md`](../README.md) と [`configuration.md`](configuration.md) を参照してください。

## Test categories

### Unit test

設定validation、term/lease計算、TTL、health閾値、timeout、sequence、duplicate/stale判定、VIP/service結果、永続化を検証する。

### State machine test

正常起動、promotion、demotion、graceful failover、health failure、lease喪失、peer喪失、Witness喪失、cleanup失敗、Maintenance、Failedからのrecovery、再起動reconcileを検証する。

F-04では、`Active → QuorumUnknown → begin demotion`、authority再取得なしの`StopService`開始、既存demotion順序、Active/Degradedの既存動作、Isolated/RecoveryPendingを含む非resource-holding stateの拒否を検証する。

### Protocol test

HELLO、heartbeat、state通知、promotion/demotion通知、lease request/grant/renew/release、protocol version不一致、cluster/node ID不一致、認証失敗、stale term、stale heartbeat、duplicate messageを検証する。

### Property test

- Nodeはtermを独自に増加させない
- stale term/lease/session/sequenceを受け入れない
- duplicateで副作用を二重実行しない
- health check成功前にActiveにならない
- cleanup未確認後にStandbyまたは自動promotionしない
- conservativeでWitness不在中に自動promotionしない
- 保存OperationPhaseだけで処理再開しない

### Integration and failure injection

以下を必須とする。

- 正常起動、正常promotion、正常demotion、graceful failover
- Activeプロセス停止、Mikagamiだけkill、serviceだけ停止
- service stop timeout、VIP取得失敗、VIP解放失敗
- Node間通信断、Active-Witness通信断、Standby-Witness通信断、Witness完全停止
- Node側local expiry到達、stale heartbeat、stale term、duplicate message
- Node/Witness再起動、Witness term永続化破損
- promotion/demotion途中でMikagami停止
- health check連続失敗
- 両Nodeからforce操作
- availabilityモードでのsplit-brain可能性
- conservativeモードで不明状態からpromotionしないこと

### Restart/recovery

保存OperationPhaseやoperation_idから処理を再開せず、実際のVIP、service、peer、Witness、term、leaseを再観測して`RecoveryPending`からreconcileすることを検証する。

localhost integrationでは`127.0.0.1:0`のephemeral portと`std::thread`を使用し、TCP上のHELLO/HELLO_ACK成功、Nodeごとの独立sequence namespace、認証済みidentity不一致、PSK不一致、HELLO以外の初回message拒否を検証する。

connection managerのpure testではcanonical direction、stale/duplicate cross-connection sequence、新しいincarnation、retired session拒否、8件のbounded history、canonical connection replacement、拒否候補によるstate非汚染を検証する。

localhost real TCPではmanager採用後のheartbeat一往復、独立sequence namespace、high-water更新、NodeStatusPayload観測、wrong message、wrong session、connection保持を検証する。

pure livenessでは2999ms/3000ms/9999ms/10000msの境界、invalid threshold、巨大elapsed、決定性を検証する。

last-success trackerでは初期`NotObservedYet`、成功観測後の`Healthy`、閾値境界、成功によるrefresh、同一時刻、時刻逆行時のエラーと状態保持、決定性を検証する。

heartbeat integrationでは、accepted HEARTBEAT/HEARTBEAT_ACK後のtracker更新、認証・identity・session・type・replay不備時の未更新、high-water commit後のtracker時刻逆行、inbound ACK送信前の更新を検証する。周期schedulerやduplex event loopは別工程である。

established peer dispatcherでは、Node messageの分類、handshake/Witness messageの拒否、共通identity検証、stale/duplicate、clean EOF、Pending取得時の未commit、明示commit、double commitを検証する。dispatchだけでliveness、NodeState、副作用が変化しないことも検証する。

heartbeat runtimeでは、dispatcher経由のinbound/outbound one-shot round-trip、送信直後の未更新、outstanding二重開始、unsolicited ACK、Pending種別不一致、tracker時刻逆行、ACK送信前のinbound更新、non-heartbeat interleavingを検証する。

peer runtimeでは、1 call/1 message、HEARTBEAT/ACK・STATE_ANNOUNCE/ACK・Promotion/Demotion messageの内部処理、各handlerのcommit境界、dispatcher/runtime errorの伝播、EOFの非authority扱い、再受信をcallerへ委譲するownership境界を検証する。STATE_ANNOUNCEのcommit-before-ACK、観測値、liveness非更新、独立したoutstanding、unsolicited ACK、二重handlerも検証する。

Promotion runtimeでは、intent送信後のoperation_id付きoutstanding、二重送信拒否、intent observationとhigh-water commit、ACK/BLOCK/UNKNOWNの明示的応答とcorrelation、unsolicited・wrong-operation responseのcommit前拒否、`PROMOTION_COMMITTED` observationとhigh-water commit、liveness・HeartbeatOutstanding・PromotionOutstanding非変更、cloneによる二重受理防止を検証する。

Demotion runtimeでは、`DEMOTION_INTENT`のobservationと明示的ACK交換、`DEMOTION_ACK`のoperation_id correlationによるcommunication-level DemotionOutstanding完了、`DEMOTION_COMMITTED`のobservation/high-water commit、各outstanding・liveness非変更、cloneによる二重受理防止を検証する。`DEMOTION_ACK`はresource cleanup proofではなく、`DEMOTION_COMMITTED`は別の専用ACKやoutstanding completionを持たない。Demotion 3 messageはすべて内部routingされるが、actual service/VIP/lease demotionは実行しない。

Witness Runtime Stage 1では、9種類のmessage分類、Node peer messageとのendpoint境界、4種類のrequest送信と単一outstanding、送信失敗時のsequence非再利用、request/responseのsemantic acceptance後commit、Protocol v1 response matrix、unsolicited・wrong ID・wrong response kindのcommit前拒否、Pending cloneの二重処理防止、identity/session/replay境界、response送信primitiveの種別制限、livenessおよびNode HA state非変更を検証する。authority、lease persistence、boot_id復旧は対象外である。

Witness Runtime Stage 2では、初期化、same-boot load、process restart、boot_id mismatch、missing/corrupt/unknown/inconsistent state、cluster mismatch、既存state上書き防止、symlink/non-regular path拒否、atomic save/reload、permissionおよび保存失敗を検証する。monotonic値は同一boot内の数値domainとして扱い、lease expiry decisionやStage 1 handlerとの統合は対象外である。

Witness Runtime Stage 3では、GET_TERMのrequest commit後のread-only projection、ReadyのNone/Active mapping、monotonic remainingと0境界、Unknown/NotReady/clock failureのfail-closed、request_id echo、CommonFieldsとTERM_STATUS payloadのterm/lease一致、response送信失敗時のstate非変更を検証する。term increment、lease mutation/expiry、Stage 1以外のauthority統合は対象外である。

Stage 3.9のpolicy testsでは、LEASE_REQUESTについてobserved_termのless/equal/greater、10秒以外のTTL、LeaseStateのNone/Active/Unknown、term exhaustion、checked deadline、独立canonical UUIDv4 lease_id、CSPRNG/clock failureを検証する。deterministic LeaseRejectはauthority stateを変更せずjournal・watermarkと一回でcommitし、pre-commit failureはgenerationをconsumeしないことを確認する。Duplicate grant/reject、session/sequence変更、remaining再計算、deadline非延長、identity不一致、remaining zero、Retired/Stale、GenerationGap、JournalFull、persistence failure、response send failure、restart/retryも対象とする。LEASE_RENEW/LEASE_RELEASE authorityおよびexpiry processingは対象外である。

Witness Persistence Stage 2.0.1では、request_idの128-bit random UUID相当形式・再利用禁止・semantic fingerprint、sequence/sessionと分離したretry identity、Duplicate/Conflict/NotFound lookup、64件bounded journal、safe retirement proofのないcapacity full時fail closed、journal corruption、duplicate record、malformed recordを検証する。F-03では通常loadがlegacy stateを変更せず`MigrationRequired`で停止すること、明示的migrationだけがF-01.1 transactionを通してv2へ移行すること、pre-canonical failure後のmarker cleanup失敗がRecoveryRequiredになること、current v2/missing/corrupt/recovery markerを区別することも検証する。unknown version/downgrade拒否、authority state・journal・retirement metadataのcandidateを1回のdurable saveでreloadできること、Stage 3 GET_TERMがjournalを変更しないことも検証する。

Stage 2.0.2の設計検証では、LEASE_REQUEST/RENEW/RELEASEの`mutation_generation`がrequesterごとに単調増加し、新規requestとretryでそれぞれ増加・再利用されること、fingerprintにgenerationが含まれること、journal eviction後にwatermark以下をRetired/Stale、`watermark + 1`だけをNewEligible候補、それを超えるgenerationをGenerationGapとして拒否することを確認する。既存fieldだけでは同一termまたは同一lease lifecycleの古いretryを区別できないケースも固定する。Protocol v1 correction後のwire型・canonical CBOR・HMAC対象・fixed vectors更新と再freezeを確認済みである。

Stage 2.0.3では、watermark=Nに対するN+1のNewEligible、N以下のRetired/Stale、N+2以上のGenerationGap、0拒否、u64::MAX exhaustion、requester別namespace、one-outstanding、persist-before-sendを検証する。crash前送信、partial send、response loss、Witness commit後のretry、response受理後のlocal clear前crash、deterministic rejectのgeneration消費、commit前transient failureの非消費、counter rollback/corruption、node_id reuse、Node/Witness restart、valid-old Witness snapshot rollback limitationを確認する。journal GC後はLEASE_REQUEST/RENEW/RELEASEそれぞれについてsuccess推測を禁止し、再観測またはRecoveryPendingとなること、demotionがrelease待ちで遅延しないことを確認する。Stage 2.1 journalの実装済みbehaviorを検証し、Stage 4 authorityは対象外である。

Stage 4ではLEASE_REQUEST authorityのpolicy、atomic authority+journal+watermark commit、Duplicate/Conflict/RetiredStale/GenerationGap、LeaseState、term/TTL/deadline/lease_id、response loss・restart/retryを検証する。LEASE_RENEW/LEASE_RELEASE authority、expiry、Node allocatorは対象外である。

Stage 5ではLEASE_RENEW authorityについて、Activeのterm・lease・holder一致、`now < deadline`境界、TTL 10秒、`now + 10秒`のdeadline更新、term/lease identity非変更、atomic deadline+journal+watermark commitを検証する。None、Unknown、期限切れ、stale/future term、wrong lease/holder、metadata欠落、clock/overflow、JournalFull、persistence failureも対象とする。Duplicate LeaseRenewedの非再延長、current deadlineからのremaining再計算、後続renewal後の古いretry、remaining zero、identity mismatch、Duplicate reject、RetiredStale、GenerationGap、response loss/restartを検証する。LEASE_RENEW authorityは実装済みであり、LEASE_RELEASE authority、expiry processing、Node allocatorは未実装である。

Stage 6ではStage 5.9で固定したLEASE_RELEASE policyを検証する。期限内・期限切れのmatching Active release、term/lease_id/holder不一致、None、Unknown、metadata不整合、Conflict、GenerationGapを対象とし、deterministic rejectとpre-commit fail closedを区別する。成功時のterm維持、lease metadata全消去、LeaseReleased result（`released`）、journal・watermarkとのatomic commit、post-release response context、response send failure後のretryを確認する。

さらに、成功Duplicateがcurrent state Noneを要求せず、後続leaseを変更しないABAケース、Duplicate rejectの再生、Retired/Staleで成功・失敗を推測しないこと、generationを消費しないことを固定する。Stage 10では、歴史的release payloadがT/L1、current envelopeがT+n/LnまたはT+n/Noneでもexact outstandingだけをdurably clearし、Lnを変更しないことを確認する。wrong historical lease/termは拒否し、LEASE_RELEASEがservice/VIP停止やfencingを証明せず、Node local demotionがrelease応答を待たないことも確認する。Stage 6でLEASE_RELEASE authorityは実装済みであり、expiry processingとNode allocatorは未実装である。

### Stage 6.9 Witness lease expiry processing policy tests

expiry実装では、Activeについて`now < deadline`のno-op、`now == deadline`と`now > deadline`の成功、term維持、lease_id・holder・TTL・deadline消去、journal・generation watermark非変更を検証する。Noneのno-op、Unknown/NotReady/incomplete metadata/clock failureのfail closed、persistence failure時の旧Active維持、same-boot restart前後の判定、boot_id変更時のNotReadyも対象とする。

GET_TERMのexpired-but-unprocessed Active（remaining 0）とexpiry commit後のNone、LEASE_REQUESTのimplicit expiry禁止、expiry後のgrant、renew・expiry・releaseの直列化、stale snapshotによるclear/resurrection防止を確認する。release先行・expiry先行、Duplicate LeaseReleasedの歴史的replay、expiry後の古いLeaseGrant/LeaseRenewedのfail closed、Duplicate LeaseReject、ABAでL2を変更しないことも固定する。timer早起動、scheduler遅延、Protocol message/request_id/mutation_generation非生成、watermark非消費を確認する。expiryはfencingやservice/VIP停止を証明しない。

Stage 7でWitness lease expiry maintenance primitive、Stage 8でそのscheduler/runtime integrationを実装済みである。Node allocator、Node demotion integrationは未実装である。

### Stage 8 scheduler/runtime tests

`WitnessExpiryScheduler`について、deadline前のWait、境界時・超過時のexpiry、None idle、Unknown/NotReady/clock failureのretry、cancel可能な待機、wait中にauthority lockを保持しないことを検証する。renew後のold timer、release後のold timer、L1 expiry→L2 grant後のstale timerがcurrent authorityを変更しないことを固定する。schedulerはrequest_id、mutation_generation、journal、watermarkを生成・変更せず、GET_TERMとLEASE_REQUESTの既存read-only/implicit-expiry禁止 semanticsを維持する。

### Stage 9 Node mutation persistence tests

Stage 9では、Node専用persistent format v1、明示的bootstrap、既存state overwrite禁止、missing/corrupt/unknown versionのfail closed、cluster/node identity検証、canonical initialization_idを検証する。`highest_started_mutation_generation`の初期値0、最初のgeneration 1、u64::MAXの最終allocate、wrap/reset禁止、最大1件のkind-independent outstandingを検証する。

beginはgeneration、fresh request_id、完全なLEASE_REQUEST/RENEW/RELEASE semantic payloadを一つのdurable candidateへ保存し、persist成功前はsendable resultを返さない。persist failureでは旧stateを維持する。restart/reconnect/response lossではrequest_id、generation、kind、observed_term/priority/TTL、term/lease_id/reasonを完全に復元し、session_id、sequence、HMAC、wire bytesを復元しない。current term/leaseで保存済みpayloadを書き換えない。

completionはrequest_id・generation・kind一致を要求し、AcceptedSuccess、DeterministicReject、RetiredStaleだけをclear可能とする。Conflict、GenerationGap、transient/unknown result、mismatchはoutstandingを維持する。completion save failure、clear前crash、successful clear後の次generation、generation rollback、state loss、同じnode_idの再利用、valid old snapshot rollback limitationを検証する。local demotionがoutstanding Witness mutationを待たないことも確認する。

### Stage 9.9.2 typed outcome protocol tests

`POLICY_REJECT`、`RETIRED_STALE`、`CONFLICT`、`GENERATION_GAP`、`TEMPORARILY_UNAVAILABLE`のcanonical serialization、unknown code拒否、HMAC対象化、code改ざん検出を実装・検証した。各codeのround-trip、reason保持、reason/code改ざん時の`InvalidMac`、既存success responseとの相関を固定する。既存固定vectorはLeaseReject非関連のため不変であり、LeaseRejectのtyped wire vectorを追加した。

Authority mappingでは、LeaseRequest/Renew/Releaseのdeterministic rejectとDuplicate reject、RetiredStale、Conflict、GenerationGapを個別に検証している。JournalFull、NotReady、Unknown authority、clock/CSPRNG/deadline/persistence failure、authority lock poisonは、現在の実装では安全なresponse境界に到達しない場合にerror/no responseとしてretainする。どの場合もauthority/journal/watermarkを不必要に変更せず、no response、timeout、transport loss、malformed/auth/replay/wrong request_id/wrong response kindはterminal completionにならない。

response loss、timeout、malformed/auth/replay/wrong request_id/wrong response kindはterminalにせずexact retryとする。成功responseのsemantic mismatch、RetiredStaleのrequest kind別reconcile、LEASE_RELEASEDがservice/VIP cleanupを証明しないこと、LEASE_RENEWのRetiredStaleがlocal deadlineを延長しないことは、Stage 9.9.2およびWitness authorityの下位層テストを含めて検証する。Stage 10直接テストでは、これらのresponse分類境界をLeaseRequestの実TCP経路で確認し、3種類のfresh successと各success semantic mismatchを直接確認する。現StageではRust wire実装とgolden vectorは変更しない。

LEASE_REQUEST/RENEW/RELEASEごとのgeneration 1、完全なsemantic payload、reload/reconstructionの一致、request_idの再生成禁止、session/sequence/HMAC/wire bytes非永続化、persist-before-send、restart後のexact retry、completion後のgeneration維持、u64::MAX exhaustionを固定する。process-local mutation Mutexにより同時beginの重複generationを防ぎ、Mutex poisonはfail closedとする。Node mutation persistenceのテストはWitness authority、journal、watermarkの仕様を変更しない。

### Stage 10 Node durable Witness mutation runtime tests

Stage 10の直接テスト範囲を、実装済みの内容と未統合の内容に分ける。

実装済みかつStage 10境界で直接テスト済み：

- LeaseRequest、LeaseRenew、LeaseReleaseのfresh success、request correlation、AcceptedSuccess、durable completion、outstanding clear
- durable outstandingを再ロードしたprocess/runtimeからのexact retry（request_id、generation、kind、semantic payload維持）
- response loss後のexact retry、send/transport failure、wrong request_id、wrong response kind、遅延した旧response
- LeaseGrant、LeaseRenewed、LeaseReleasedのsuccess semantic mismatch
- `POLICY_REJECT`、`RETIRED_STALE`、`CONFLICT`、`GENERATION_GAP`、`TEMPORARILY_UNAVAILABLE`のtyped分類とretain/clear動作
- 同じtyped codeでreasonを変更しても分類が変わらないこと
- terminal response後のcompletion persistence ambiguityでcompletionを報告せず、次generationを禁止すること
- F-01 recovery marker存在時に新しいWitness mutationを送信しないこと
- F-02 historical Duplicate LeaseRelease（fresh LeaseReleaseとは別の不変条件）

実装済みだが主に下位層でテスト済み：認証、HMAC、canonical CBOR、transport replay、Witness journal Duplicate/Conflict/RetiredStale/GenerationGap、authority側のLeaseRenew/LeaseRelease policy、および一部のfilesystem fault boundaries。これらはStage 10の全mutation testで重複検証しない。

未実装またはStage 10統合テスト対象外：retry scheduler、reconnect manager、GET_TERM reconcile、NodeState/local expiry、service、VIP、promotion、demotion、fencing、実Witness authorityとの永続化を伴うend-to-end連携。Stage 10はmutation runtimeのone-shot境界だけを扱う。fresh LeaseReleaseの生成は既存のStage 10内部runtime経路に限定し、通常のproduction callerへ一般的なLeaseRelease生成権限を公開しない。既にdurableなoutstandingのretry/recoveryは既存経路で継続可能である。

restart/retryではrequest_id、generation、kind、semantic payloadを再利用することを確認する。transport sequenceは現在のProcessSessionから再構築されるが、このStage 10テスト記述はsequence continuityの直接assertionを主張しない。completion persistence failure後もoutstandingを保持し、old responseが次generationをclearしないことを検証する。Node mutation persistence lockがTCP送受信中に保持されないこと、Stage 10がNodeState、local lease expiry、service/VIP、promotion/demotion、fencing、automatic retry/reconnectを変更しないことも確認する。

### F-01.1 persistent recovery transaction tests

Recovery Transaction Contract v1.1では、テスト結果を次の分類で記録する。`SPECIFIED`は設計契約、`STRUCTURALLY ENFORCED`は実装構造、`DIRECT UNIT TEST`は純粋な単体assertion、`DIRECT CALLER TEST`はNode/Witness caller境界、`STAGE10 INTEGRATION TEST`はStage 10の実TCP経路、`NOT YET TESTED`は未検証、`REAL POWER-LOSS NOT TESTED`はfault injectionでは証明できない実電源断である。分類を混同して、設計表だけを実テスト済みとは記載しない。

R-01/R-02/R-03/R-06の実装段階で必須の直接テストは次のとおりである。

- Recovery v1.2で、同一canonical pathのHandle A/Bが同じResolvedStorePath、PathIdentity、process-global registry entryおよび実Recovery transaction lockを共有することを、parent symlink＋`..` aliasとtest-only handshakeで直接assertする（`DIRECT UNIT TEST`）。`Arc`のpointer identity自体は直接assertせず、registry構造とlock境界で共有を確認する。sleepによる競合再現は使用しない。
- reader/writer相互テストは、実Recovery lock直前のcontender到達、holder解放、lock後の処理、確定canonical観測を順序付ける（`DIRECT CONCURRENCY TEST`）。ただし`std::sync::Mutex`内部のOS waiter状態そのものは独立には証明せず、相互排他は標準ライブラリMutexの契約に依存する。
- writer active中のreaderは中間marker／canonicalを返さず、writer終了後に確定したcanonicalを再観測することをRecovery層で直接assertする。Node/Witness callerによる全結果の組合せは未網羅である。
- Handle Aのuncertain marking後、別handleのNode/Witness loadが拒否されることを直接assertする（`DIRECT CALLER TEST`）。save、begin、completion、scheduler、authoritative GET_TERMの全caller組合せは未網羅である。
- Recovery v1.2では、parent symlink＋`..` alias、direct pathとのResolvedStorePath／marker共有、相互方向のuncertainty共有、reader/writer alias直列化、nonexistent final component、final-component symlink拒否を実filesystemで直接assertする（`DIRECT UNIT TEST`）。
- WitnessのS0-derived candidateを、S1のterm、authority、journal、requester watermarkの後にcommitし、PREPAREなしで拒否され、S1の4要素が不変であることを`commit_candidate`経路で直接assertする（`DIRECT CALLER TEST`）。
- markerが既に存在する状態でPREPARE no-replace installを実行し、既存marker bytesが変わらずcanonical mutationへ進まないことを確認する（`DIRECT UNIT TEST`）。
- cleanup directory fsync ambiguity後にmarker pathnameが消えていても、Recovery層がuncertain状態を保持することを直接assertする（`DIRECT UNIT TEST`）。全callerのsecond-handle拒否は未網羅である。
- hard-link source aliasとcandidate tempがtransaction-unique nameになり、stale candidateを再利用しないことを確認する（`DIRECT UNIT TEST`）。fresh process全体の再起動・garbage cleanup組合せは未検証である。
- completion ambiguityではcanonical outstandingが必ず残るとは仮定せず、completion resultを返さず、normal operationとN+1 generationをrecovery gateで拒否する（`DIRECT CALLER TEST`）。

P0-P10 matrixは`SPECIFIED`として扱い、fault injectionまたは実際のlock取得到達を確認する決定的handshakeで直接assertした個別境界だけを`DIRECT UNIT TEST`または`DIRECT CALLER TEST`へ昇格する。Recovery v1.2のN-01／N-02では、上記の個別境界を直接テスト済みとし、未実装の組合せ、実電源断、OS crash、filesystem power-loss durabilityは`NOT YET TESTED`または`REAL POWER-LOSS NOT TESTED`である。

Recovery Metadata v1の実装には、temp file fsync、marker install／directory fsync、candidate fsync、canonical rename／hard-link、canonical parent fsync、marker cleanup／directory fsyncのfault-injection seamがある。現行テストはこれらの一部をRecovery unitおよびNode/Witness caller境界で直接assertしており、全てのWitness mutation callerとfault pointの組合せを網羅するものではない。

- canonical mutation前の失敗では旧stateを維持し、Nodeは送信しない
- candidate fsync失敗とcanonical installの明示的な未変更失敗は、PREPARE marker cleanupとdirectory fsync確認後だけPreCommitFailureとしてretryを許可し、cleanup失敗時はuncertainとする
- PREPAREが不確定でもcanonical mutationは行わない
- canonical mutation後の`CommitOutcomeUnknown`ではstoreをuncertainとしてload／save／begin／complete、Witness mutation、GET_TERM、schedulerを通常実行しない
- Node completion ambiguity後にoutstanding=Noneを見て次generationを開始しない
- Witness ambiguity後にLeaseGrant／Renewed／Released、PolicyReject、Duplicateを返さない
- process restartでmarkerが残る場合、canonicalがOLD／NEWいずれでもRecoveryPending／NotReadyとする
- marker cleanup ambiguityはfalse-positive recoveryだけを許可する
- markerのmissing／corrupt／unknown version／symlink／non-regular／identity mismatch、OLD／NEW／NEITHER fingerprint、second store handleを検証する
- same-boot process restart、OS boot_id change、power/storage crash想定を分離する

fingerprint一致、parse成功、read成功、generation、journal、watermark、再fsync成功だけをdurability proofとして扱わない。管理者recoveryは新しいconfirmed durable baselineを確立した後にのみmarkerをcleanupできることを検証する。P0〜P10は仕様matrixとして保持し、直接assert済みの境界と未検証の境界を分けて記録する。全matrixをNodeとWitnessで確認済みとは扱わない。

### Stage 7.1 authority mutation serialization tests

実スレッドを使い、RENEW対expiryとRELEASE対expiryを同一mutation boundaryで競合させ、lock取得順にかかわらずstale candidate、lost update、resurrectionが発生しないことを検証する。L1をexpiryしてterm 7のNoneへ遷移し、LEASE_REQUESTでterm 8/L2を作成した後、L1由来の古いexpiry・renew・releaseがL2を変更しないABAケースも固定する。Mutex poisonはtest-local lockで再現し、`AuthorityLockPoisoned`、authority state不変、journal/watermark不変のfail-closed動作を確認する。response/network I/Oはmutation lock外であり、GET_TERMはread-onlyのままとする。

## Safety invariants

- heartbeat lossだけでpeer deathと判定しない
- Witnessはfencingではない
- term/leaseはfencing tokenではない
- fencingなしでは旧Active停止を保証しない
- promotion順序は`VIP → service → health → gratuitous ARP → Active`
- GARP失敗時はActive確定しない
- Node側local expiry到達時、正常なActiveは直ちにdemotionを開始する
- safety marginは二重Activeを保証しない

## Test environments

Apple Container Machineでは、状態機械、protocol、Witness、service lifecycle、health check、timeout、通信断、再起動、失敗注入を検証する。

実Linux VMまたは物理Linuxでは、実NIC上のVIP、ARP cache、gratuitous ARP、interface down/up、network manager競合、OS hang、電源断、VIPを保持したままのプロセス停止を最終確認する。

VIP、GARP、L2ネットワーク挙動について、Apple Container Machineの結果だけで実環境の動作を保証しない。

## Stage 11 Lease Authority Integration Test Design

Stage 11.1では、runtime-onlyのNodeLeaseAuthority、fake monotonic clock、safe deadline、renewalの旧deadline再確認、demotion latch、およびStateMachineの明示的authority-gated入口を実装した。validated grant、ownership eligibility、reset capabilityのproduction creatorはまだ作成せず、RecoveryReady・release-clear・zero-resourceをcaller assertionで代用しない。これらの純粋な境界は`DIRECT UNIT TEST`として扱う。Stage 10のtimed mutation adapterはattempt_startを返すが、listener/mainへの継続runtime統合と実resource backend接続はまだ`SPECIFIED`である。

### Mutation outcome contract

| mutation | outcome | durable disposition | authority/state effect | retry/reconcile | permission |
|---|---|---|---|---|---|
| LeaseRequest | AcceptedSuccess | existing terminal completion | grant identityとsafe deadlineを検証後、PromotionAuthorized候補 | late/invalidならusableにしない | promotion可はguard完了後のみ |
| LeaseRequest | PolicyReject | terminal clear | successを推測しない | CandidateをStandby等へ戻す | promotion不可 |
| LeaseRequest | RetiredStale | terminal token clear | grant成功を推測しない | reconcile必須 | promotion不可 |
| LeaseRequest | Conflict/GenerationGap | outstanding保持 | authority不明 | RecoveryPending/reconcile | promotion不可 |
| LeaseRequest | TemporarilyUnavailable/transport/auth/correlation | exact outstanding保持 | authorityなし | 同一mutation retry | promotion不可 |
| LeaseRenew | AcceptedSuccess | terminal completion | response検証とdurable completion後にdeadline置換 | 次renewは新期限から | 継続可はsafe deadline内のみ |
| LeaseRenew | PolicyReject/RetiredStale | terminal clearだが成功推測なし | current authorityを延長しない | reconcileまたはdemotion | promotion不可 |
| LeaseRenew | Conflict/GenerationGap/temporary/transport | outstanding保持 | 旧deadlineを延長しない | exact retry/reconcile | safe boundaryでdemote |
| LeaseRelease | AcceptedSuccess | terminal completion | release結果を履歴として受理 | local cleanupは既に先行 | Standby commit条件へ |
| LeaseRelease | PolicyReject/RetiredStale | terminal clearまたはreconcile | historical resultからcurrent authorityを推測しない | exact仕様に従いreconcile | resource cleanupを待たせない |
| LeaseRelease | Conflict/GenerationGap/temporary/transport | outstanding保持 | release未確認 | retry/reconcile | local cleanup後のStandby gatingのみ |

`AcceptedSuccess`と`PromotionAuthorized`は同義ではない。相関済みgrantでもremainingがmargin以下、responseがsafe deadline後、clock failure、Recovery uncertaintyならauthorityはusableではない。

### Timing and failure schedule

TTL 10秒、renew interval 3秒、margin 2秒の場合、論理mutationの最初のattemptの送信直前をtiming originとする。即時responseならWitness expiry相当は`origin+10秒`、safe deadlineは`origin+8秒`である。Witness/transportが遅れても、同一`request_id`・`mutation_generation`・kind/payloadのretryで後続attemptの時刻へoriginを更新してはならない。renew dueはgrantの受信・検証完了時刻を基準とし、安全期限とは別に扱う。duplicate grant/renewはcurrent durable deadlineからremainingを再計算する。renew responseが旧safe deadline前に到着しても、durable completion後に旧deadlineを再確認する。completionが旧deadlineを跨いだらrenewed authorityをinstallせずdemotionを維持する。safe deadline後のresponse、remaining以下margin、trusted timingなしはusableではない。

peer消失だけではpromotionしない。Witness unreachable、grant response loss、Witness grant後のNode timeout、renew response loss、Witness NotReadyでは、Candidateはauthorityなし、Activeはsafe deadlineまで継続後にlocal demotionとする。Witness restart、Node restart、clock failure、overflow、remaining以下marginは旧authorityを復元せずfail closedとする。cleanup成功後にLeaseRelease responseが失われてもlocal cleanupをrollbackせず、outstandingのexact retry/reconcileを行う。RecoveryPendingでpeerが不在でもfresh LeaseRequestで回避しない。

### Direct and integration tests to add

- `DIRECT UNIT TEST`: Candidateからauthority-gated promotion境界、Active/Degradedのauthority gate、RecoveryPendingのlocal cleanup entryを検証する。
- `DIRECT UNIT TEST`: fake monotonic clockでgrant、remaining以下margin、overflow、候補期限切れ、renew成功、旧deadline跨ぎ、late grantによるlatch解除禁止を検証する。
- `SPECIFIED`: Stage 10 timed mutation adapterがtransport送信直前のattempt_startを公開し、authority install/renewがdurable completion後の境界でのみ行われることを確認する。Node authority callerを含む実transport経路の直接assertionは未実装である。
- `DIRECT CALLER TEST`: Conflict、GenerationGap、RetiredStale、TemporarilyUnavailableのNode mutation dispositionとpromotion抑止を確認する。
- `DIRECT CALLER TEST`: RecoveryPending、Failed、Maintenance、IsolatedがLeaseRequestをauthority bypassに使わないことを確認する。
- `INTEGRATION TEST`: Witness authorityのgrant/renew/releaseをNode state machineへ接続し、service/VIP actionの前にlease gateが成立することを確認する。
- `INTEGRATION TEST`: Witness unreachableでもlocal demotionがStopServiceから開始され、LeaseRelease待ちにならないことを確認する。
- `INTEGRATION TEST`: process restartが旧runtime deadlineを復元せず、outstanding mutationだけを同一identityでretryすることを確認する。
- `SPECIFIED`: 3秒遅延grant、retryによるtiming origin reset、duplicate remaining、AcquireLease→VIP、VIP→service、service→health、GARP→Active各境界でのlease lossを確認する。fake-clock unit testは実transport遅延やOS scheduling保証を代替しない。
- `SPECIFIED`: Degraded→Activeのexact authority check、renew completionが旧deadlineを跨ぐ場合、late renewがdemotion latchを解除しないことを確認する。
- `SPECIFIED`: restart後の成功LeaseRequestだけではRecoveryReadyにならないこと、VIP残存、service残存、両方残存、unknown observationのcleanupを確認する。
- `SPECIFIED`: RecoveryPendingがWitnessなしでcleanupできること、unresolved LeaseReleaseがcleanupを阻止せずfuture promotion/N+1を阻止することを確認する。
- `SPECIFIED`: resource-owning QuorumUnknownがCandidateを経由せずdemoteでき、availability modeがWitness leaseを要求しないことを確認する。
- `NOT YET IMPLEMENTED`: Apple Container Machineでの実VIP/ARP、実LinuxでのOS hang・電源断・fencing相当の確認。

Stage 11.2の直接unit testは、fresh controllerのRecoveryBlocked、test-only reconciliation、ZeroResourceの取得拒否、期限・clock failure時のusable authority検証、ResourceOwning/Unknownのdemotion latch、late grantの拒否、一回限りcheckpoint permission、controller内部のunresolved LeaseRelease block、completion時のLeaseRelease再検査、availability modeのWitness非依存を検証する。private constructorによるcontroller再生成防止は、Rustのmodule visibilityとproduction call siteの静的検査で確認する。これらのテストは実VIPやserviceを観測・操作しないため、resource ownershipそのもの、実cleanup、GARP、実Linux failoverの証明ではない。実resource executorがtrusted ownership boundaryを通知し、不確実時はResourceOwning相当としてcleanupへ進む接続は後段である。CLIはbootstrap scaffoldingに留まり、live daemon owner/event loopは未実装である。

既存のStateMachine pure testsはNodeState/OperationPhaseの順序を維持して残す。Stage 11.1のauthority gate testsとStage 10 timed adapterはruntime primitiveの直接テストであり、listener/mainからの継続実行、実resource backend、Witness unreachable時のlocal demotion integrationは依然として`SPECIFIED`または`INTEGRATION TEST`待ちである。

### Stage 11.3 ResourceExecutor future tests

Stage 11.3の以下は将来テスト計画であり、現在は未実装・未検証である。deterministic fake NetworkBackend/ServiceBackendを使い、sleepなしでcommand result、observation result、authority timing、completion result、restart pointを独立に制御する。

Stage 11.4では、ResourceExecutorのdeterministic fake backend primitive testとして、action diagnosticとtrusted observationの独立性、timeout/error後のPresent/Absent/Running/Stopped保持、observation unavailableのUnknown分類、healthとserviceの分離、GARPとVIPの分離、cleanupのauthority非依存、deterministic fake backendによるruntime変換を実装済みで検証する。Rustの静的・module visibility evidenceとして、trusted observationのprivate field/constructor、sealed backend trait、任意のproduction moduleからのbackend実装拒否、ResourceExecutorにNodeState/controller mutation capabilityがないこと、trusted runtime factにserde/persistence/restore pathがないことを確認する。これはprocess restartやRust visibilityをruntime testで証明するものではない。実netlink、実systemd、command、arping、実resource observation、process restart recovery、end-to-end HAは引き続き将来テストである。

Stage 11.6Aでは、Linux NetworkBackendの構成validation、IPv4-only、`IFA_LOCAL`優先のlocal address identity、interface/prefixを含むVIP identity、対象interface外entryの除外、Present/Absent/Unknown分類、netlink sequence/sender validation、GARPの引数・exit status・signal・timeout/cleanup mappingを特権なしのpure testで検証する。macOS上のこれらのテストはmappingと契約境界の証拠であり、実kernel netlink、実interface、実VIP、実arping、kill/reapの動作を証明しない。実Linuxでは、権限を分離したnetwork namespaceまたはContainer Machineでadd→Present、delete→Absent、interface/query failure→Unknown、multipart netlink、GARP cleanupを別途検証する。Stage 11.6BではLinux systemd ServiceBackendの直接argv実行、loaded/running・loaded/inactive/deadだけの観測分類、malformed/duplicate/query failureのUnknown分類、4KiB上限を超えたsystemctl出力のUnknown分類、action diagnosticと観測の独立性、action timeout後のkill/wait/reap、health stdoutを解釈・保持しないHealthy/Unhealthy/Unknown分類、およびpipe bufferを超えるhealth出力のexit-status分類をtest-only executable fakeで検証する。これらはreal systemd、real service transition、daemon、automatic failover、fencing、実HA resource operationを証明しない。

Stage 11.7では、Linux composition rootが既存のNetworkBackend、systemd ServiceBackend、ResourceExecutor、ResourceWorkflow、authority owner、NodeMutationStoreを接続する境界を検証する。`LinuxPlatformConfig`の明示的絶対arping path、relative/empty path拒否、PATH検索・fallbackなし、public TOML・Node persistence・Protocolへ`arping_path`を追加しないことを確認する。startup/recoveryはVIPとserviceを再観測し、resourceが残る場合は既存Workflowのauthority-free cleanupでStopService→確認→ReleaseVIP→確認を実行する。Unknown、cleanup失敗、未解決LeaseRelease、その他のRecovery blockerではStandbyへ進まず、RecoveryPendingに留める。RecoveryPending/Initからfresh LeaseRequestを行わず、reconcile済みStandbyからの明示的promotionだけが既存authority pathへ進む。statusはauthority取得・cleanup・promotion・demotion・Witness mutation・health command実行を行わず、healthはUnknown/未観測とする。explicit promote/demoteはResourceWorkflowの既存順序とauthority再検査を使用し、Stage 11.7はdaemon、automatic failover、fencing、実Linux HA resource operationを証明しない。現在の直接テストはlease gate、recovery local cleanup順序、Unknown保持、public/persistent/Protocol境界を対象とする。`linux_node_runtime`のcomposition-boundary attack tests `attack_aa_restart_does_not_restore_persisted_lease_mutation_as_active_authority`、`attack_ab_resources_present_enters_recovery_cleanup_service_before_vip`、`attack_ac_stale_operation_does_not_resume_promotion`、`attack_ad_persisted_stale_lease_release_does_not_become_runtime_authority`、`attack_ae_recovery_unknown_blocks_standby_and_lease`、`attack_af_stop_success_service_unknown_blocks_vip_release`、`attack_ag_vip_delete_success_vip_unknown_blocks_standby`、`attack_ah_unhealthy_service_running_cannot_commit_active`、`attack_ai_authority_expiry_before_active_commit_cleans_up`、`attack_aj_unresolved_lease_release_blocks_standby_and_fresh_lease`、`attack_ak_repeated_promote_during_cleanup_cannot_start_again`、`attack_al_restart_during_incomplete_cleanup_stays_recovery_pending`を直接実行し、AA–ALをCOVEREDとする。AAはNode Persistent v1がruntime authorityを保存しないことを確認するため、永続化されたLeaseRenew mutationを読み戻してからfresh runtimeへ再構築する。ADは永続化されたstale LeaseRelease mutationを読み戻してからfresh runtimeへ再構築する。C2のD/Eも`c2_d_relative_arping_path_is_rejected_without_path_search`と`c2_e_invalid_absolute_arping_path_has_no_fallback`で直接検証する。これらはdeterministic fake backendを用いた構成境界の証拠であり、実Linux HA resource operationの証明ではない。

Stage 11.8では、`Daemon`と`DaemonRuntime`のdeterministic lifecycle boundaryを検証する。AM–AVのattack testsは、startup/recovery gate bypass、観測tickからのlease acquire・promotion、snapshotのside effect、health観測失敗のUnknown分類、shutdown中のbounded completion、resource-owning shutdownのcleanup未確認、RecoveryPendingのloop侵入、stale cacheのauthority化、restart時のruntime lease authority復元を拒否する。AW–AZは`resource_owning == false`でもVIPが`Present`/`Unknown`またはserviceが`Running`/`Unknown`ならclean shutdownにしないことを確認する。BAはreconciled Standbyでもresource ownershipが残ればstartupを`RecoveryBlocked`にすること、BB–BCは`Active`かつresource ownershipなしのfatal invariantを`Failed`へラッチしてtick再開を拒否すること、BDは通常の観測エラーを`Unknown`としてRunningに留めることを確認する。BE–BGは`RecoveryBlocked`のshutdown intentが`ShutdownRequested`から安全判定へ進み、再startでRunningへ戻らず、不確実な結果でStoppedにならないことを確認する。BHはActiveかつZeroResourceでもdemotionを経由し、BL相当のcleanup uncertaintyで停止完了にしないこと、BIはresource-owningかつZeroResourceでもcleanup obligationを経由し、失敗時に停止完了にしないこと、BJはnon-Active・non-owning・trusted ZeroResourceだけがshortcut可能であることをLinux runtime境界で直接確認する。テストはcaller駆動tickを使い、sleepやwall-clock待機を正しさの根拠にしない。daemonはheartbeat missingをpeer deadと判定せず、automatic failover、fencing、watchdog、quorum、実resource操作を開始しない。Linux adapterのhealth観測はdaemon tickだけが実行し、snapshot/statusはcached observationを返す。clean shutdownはtrustedなVIP `Absent`かつservice `Stopped`のZeroResourceが条件だが、lifecycleまたはcleanup obligationが残る場合はshortcutできない。

Stage 11.9では、既存Heartbeat wire契約を使う`PeerObserver`の固定peer・固定slot・deterministic fake transport境界を検証する。BK–BZはNeverSeen/Fresh/Stale/Invalid/Unavailable分類、cluster/node identity、duplicate/older sequence、authentication/malformed/transport failure、remote Active非authority、restart時のNeverSeen、snapshot purity、invalid inputの固定slotを直接検証する。CA–CIは、Heartbeat認証とsession establishmentの分離、Heartbeat単独のsession/replay window reset拒否、trusted session establishment後の低いsequence受理、切替後の旧session拒否、拒否トラフィックのfreshness非更新、再起動時のsession/Fresh非復元、session eventのHA非作用を直接検証する。CJ–CLは、新session確立時の旧Fresh観測無効化、新session最初のHeartbeatまでFreshにしないこと、同一sessionの重複establishmentでFresh・last_received・sequence windowをリセットしないことを直接検証する。replayや不正入力はlast-good receive時刻を更新しない。peer observationはdaemon tick hookでのみ更新でき、status/snapshotは送受信しない。Stage 11.9ではreal UDP、automatic failover、heartbeat timeoutによるdemotion/promotion、lease mutation、fencing、peer death declarationは未実装である。

Stage 11.10ではdeterministic fake connection/session harnessを使い、authenticated HELLO完了前のheartbeat拒否、HELLO完了の一回限りの`SessionEstablished`、EstablishedHeartbeatだけのPeerObserver配信、same-session duplicate HELLOによるFresh/last_received/sequence high-water非リセット、新sessionによる旧Fresh無効化、旧connectionからの遅延heartbeat拒否、connection lossのUnavailable分類、再接続だけではFreshにならないこと、wrong cluster/peer、protocol/authentication/malformed入力のestablishment拒否を直接検証する。session runtimeのsnapshot/status相当処理はイベントを消費せずside-effect-freeであり、HA action、lease、promotion、demotion、resource操作を開始しない。固定peer・current connection/sessionのみを保持し、invalid attemptや旧session履歴を無制限に蓄積しない。Stage 11.10はreal TCP listener、automatic reconnect、heartbeat scheduler、automatic failover、fencing、実service/VIP操作を証明しない。

Stage 11.10のconnection provenance tests DG–DIは、trustedな新generationだけがreplacementできること、delayed old Connectとold HELLOでsession rollbackできないこと、stale Connectがcurrent Fresh・last_received・sequence high-waterを変更しないことを直接検証する。DJ–DMは同一generation・同一connectionのduplicate Connectをno-opとし、同一generationの異なるconnection identity、stale Disconnect、old-generation Heartbeatを拒否することを検証する。generationはwire、Protocol v1、Node/Witness persistenceのいずれにも追加せず、remote peerが指定できないruntime-only provenanceである。generation allocatorはchecked incrementでoverflowを明示的に拒否し、履歴を蓄積しない。

Stage 11.5では、deterministic fake backendを用いてNodeAuthorityControllerとResourceExecutorを同期的なResourceWorkflowで結合し、VIP→service→health→GARP→BeforeActiveCommitの順序、各ownership-affecting stepの個別checkpoint/completion、completion失敗後のcleanup obligation、diagnosticとtrusted observationの分離、Unknownのfail-closed分類、authority-freeなservice stop→VIP release→LeaseRelease開始を実装済みで検証する。cleanupはtrustedなStopped＋Absent観測時だけlocal cleanup provenanceを生成し、controllerのlocal ownershipを確定してから、保守モードでは既存NodeMutationStoreのLeaseReleaseへ進む。通常のcrate-local callerはこのprovenanceおよびfresh LeaseRelease originを生成できず、module visibilityによってcleanup LeaseReleaseの順序を構造的に制限する。このRust visibilityはruntime testだけでは証明しない。既にdurableなLeaseReleaseのretry/recoveryと、LeaseRequest/LeaseRenewのruntime testは別の既存境界として維持する。ResourceWorkflowはNodeStateを直接変更せず、Active/Standbyのcommitは将来のouter controllerへ返すtyped outcomeに留める。実Linux privileged backend integration、Witness transport、daemon loop、real restart、network partition、end-to-end HA、実resource操作は未実装である。

Stage 11.3のcommand backend停止契約には、旧契約からの安全上の明示的訂正を含む。stop exit 0 + health非正常 + process/service absence不明はService Unknownとし、VIP releaseやStandbyへ進めない。health failure alone、PID existence alone、stop exit status aloneはConfirmedStoppedの証明としない。これはStage 11.3の将来テストであり、実装済みの証拠ではない。

- VIP add/releaseのsuccess/error/timeoutとPresent/Absent/Unknownの全組合せ。
- service start/stopのsystemd観測、command backendの弱い確度、running/stopped/Unknownの全組合せ。
- health failure、GARP timeout、authority lossの各promotion boundary。
- `checkpoint → exactly one operation → observation → completion`のpermission消費と、completion failure後のUnknown/demotion。
- VIP、service、health、GARPの各rollback、cleanup uncertainty、confirmed absenceによるZeroResource/Standby条件。
- LeaseRelease successとlocal cleanupの独立性、unresolved LeaseReleaseのfuture promotion blocker。
- action前後のprocess interruption、restart後のRecoveryPending、実resource再観測、RecoveryBlocked解除のtrusted provenance。
- availability modeのrestart/residual resourceと、conservative modeのauthority/LeaseRelease gate。
- ordinary callerによるconfirmed fact fabrication拒否。
- failure matrixの全branchと、Protocol・永続化形式を変更しないこと。
- action/diagnostic outcomeとresource observationの分離：timeout/error + trusted Present、timeout/error + trusted Absent、timeout + observation unavailableをそれぞれ検証する。
- service Running観測をcontroller ownership Unknownへ書き換えないこと、service stop confirmation failureをNodeState Failedへ分類しRecoveryPendingと混同しないこと。
- authority loss、expired lease、demotion latch、RecoveryBlocked中でもcleanupがStage 11.2 promotion permissionなしで実行可能であること。
- service stop error/timeout + trusted Stopped、およびVIP delete error/timeout + trusted Absentが、確認済みpostconditionとして順序どおりcleanupを進めること。

これらのテストを実装済みのStage 11.2 unit testや既存のpure state testと混同しない。Stage 11.3 docsは実VIP、実systemd、実netlink、実ARP、end-to-end failover、fencingを証明しない。Apple Container Machineと実Linux環境のテストは、backend実装後に別々の証拠として扱う。

### Stage 11.11 real TCP transport foundation tests

DN–EHのloopback testsは、TCP accept/connect単独では認証済みsessionにならないこと、HELLO前のheartbeat拒否、partial frame保持、同一read内の複数frame分離、16 KiB超過・truncated frameのbounded拒否、transport error/EOFのSessionRuntime通知を直接確認する。socket writeは既存のbounded frame送信境界を通り、pollはnonblockingで、テストの正しさはsleepではなくboundedなpollと`yield_now`で確認する。

DX–EHおよびcanonical-direction testは、ローカルのgeneration/connection tokenがwireから供給されないこと、古いsocketや遅延frameがcurrent sessionを巻き戻さないこと、再接続だけではFresh/Establishedにならないこと、認証済みframeだけがSessionRuntimeへ渡ることを確認する。transport step自体はHA action、lease、promotion、demotion、resource操作を開始しない。loopback testは実Linux listenerの権限差、実netlink/systemd/VIP、network partition、automatic failover、fencingを証明しない。

Stage 11.11 remediation tests EK–EOは、oversized frame、truncated EOF、fatal read、WouldBlock、fatal writeをそれぞれ確認する。terminal failureではcurrent tokenがdetachされ、partial bufferが再利用されず、次のcaller-driven `poll_session`でDisconnect/TransportUnavailableが一度だけ通知される。WouldBlockではcurrentとsessionを維持する。write failureは送信成功と扱わずcurrentをdetachし、同じfailureで自動reconnectやHA actionを開始しない。これらはdiagnostic分類とconnection teardownを分離して検証し、loopback testはpeer dead、lease authority、promotion、fencing、実resource cleanupの証明ではない。

EPはsemantic-invalid outbound messageがsocket write前に拒否されてもcurrent connectionとEstablished sessionを維持し、後続のvalid sendが同じtokenで可能なことを確認する。pre-writeのserialization/authentication failureを安全に注入できるproduction APIは追加していないため、EQ専用の危険なtest hookは設けていない。ERはfatal socket writeでのみcurrentをdetachし、次のcaller-driven pollでDisconnectを一度だけ通知することを既存EOと合わせて確認する。message preparation failureとterminal transport failureはいずれもHA actionを開始しない。

### Stage 11.12 daemon/TCP integration tests

`daemon_peer_runtime`のStage 11.12 real loopback testsは、二つのcaller-driven runtimeでTCP connect、HELLO/HELLO_ACK、SessionEstablished、heartbeat、双方のFresh observationまでを確認する。TCP connectだけではFreshにならず、HELLO前のheartbeatを受理しない。接続断はUnavailableとDisconnectへ分類されるが、peer Dead、lease、promotion、demotion、resource mutation、fencingを開始しない。Stage 12.1では別の回帰テストで、pending Disconnect後のcaller-driven automatic reconnect/rebindを検証する。

peer tickは`MAX_FRAMES_PER_TICK`を超えてframeを処理せず、残りは後続tickへ持ち越す。monotonicなtick時刻でheartbeat cadenceを駆動し、status/snapshotはsocket I/Oやpending Disconnectのdrainを行わない。local observationが失敗したtickでも、daemonはlocal errorを保持したままbounded peer maintenanceを継続し、pending Disconnectをexactly onceでdrainする。Linux composition rootはlocal runtimeを構築してからpeer transportを初期化し、startup時のlocal recoveryはinitial outbound connectより先に行う。peer listener bindまたはpeer connectが一時的に失敗してもpeerをUnavailableとしてlocal recovery contractを不必要に阻止しない。invalid configurationは引き続きconstruction failureとする。shutdownはlocal resource safety判定後にpeer transportを閉じる。

Stage 11.12のEQ–FH相当は、既存Stage 11.8のrecovery/shutdown攻撃テスト、Stage 11.11のtransport/error分類テスト、および本段階のreal loopback/bounded tick testsを組み合わせて確認する。これらは実VIP、実systemd、automatic failover、fencing、network partition、電源断、実Linux HAを証明しない。Protocol v1、Node/Witness persistence、journal/watermarkを変更しないことも回帰確認対象である。Stage 11.13ではfull Stage 11 adversarial failure matrix、restart、replay、partial I/O、connection replacement、shutdown/resource safetyを再監査する。

Stage 11.12のterminal Disconnect回帰では、write failure後に`TcpPeerRuntime`がcurrent socketをdetachしてpending Disconnectを保持し、daemon peer tickが上位のcurrent token cacheに依存せずそれをdrainすることを確認する。Disconnectは同一failureにつき一度だけSessionRuntimeへ配送され、drain完了後は明示的な`connect_once`が可能になる。pending中のinstall拒否、drain後の再接続、通常tickでの余計なDisconnectなしを確認するが、peer dead、HA判断、resource cleanupの証明ではない。Stage 12.1のautomatic reconnectはこのpending delivery後だけ試行される。snapshot/statusはpending Disconnectを消費しない。

Stage 11.13のFV–GA回帰では、local observation failure中もpeer maintenanceが継続し、HA actionを開始しないこと、およびlistener bind failureをpeer Unavailableとしてlocal recoveryから分離する境界を確認する。FV/FWはdaemon層のpeer tick継続を直接検証する。pending Disconnectの実配送とexactly-once性は下位の`TcpPeerRuntime`テストおよびコード経路で確認し、FV/FW単独の証拠とは扱わない。Stage 11.14のGGはinbound HEARTBEATから実際のHEARTBEAT_ACK wire messageを確認し、GIはHEARTBEAT_ACKに限定したdeterministic terminal send failure、失敗variant、送信試行回数を確認したうえで、受理済みheartbeatのsession-scoped high-waterが維持され、pending Disconnectへ進むことを確認する。全Linux compositionでのrecovery順序を証明するものではなく、peer transportの自動rebind/reconnectは実装しない。

Heartbeat statusの回帰では、`DaemonPeerRuntime`へ渡したcached local snapshotからActive、RecoveryPending、VIP Present、service Running、health Unhealthy、各Unknown、および`operation_phase`をpayloadへ反映することを直接確認する。Heartbeat constructionは追加のVIP/service/health観測、command実行、lease/resource mutationを行わず、未観測状態をStandby/Absent/Stoppedへ丸めない。これらはdiagnostic reportの正確性を検証するもので、peer reportをauthority、peer dead、promotion、demotion、resource cleanupの証明とはしない。
### Stage 12.1 transport recovery tests

The Stage 12.1 tests directly exercise caller-driven transport recovery with
loopback TCP where supported. They cover bounded retry delays and the 5 s
cap, reconnect after pending `Disconnect` delivery, replacement session and
connection generation, no Fresh observation before a valid heartbeat for the
replacement session, stale-session isolation, inbound listener rebind after a
runtime bind failure, shutdown suppression of pending retries, and the
distinction between runtime transport Unavailable and configuration failure.

These tests use synthetic monotonic `Instant` values and bounded tick loops;
wall-clock sleep and background retry workers are not correctness mechanisms.
They do not prove automatic failover, lease/Witness behavior, service/VIP
operations, fencing, network partition handling, or real production HA.
Linux-only socket and listener tests are compiled under the Linux target;
macOS runs the portable test set and is not required to have the same count.

Handshake deadline regression tests additionally cover silent outbound and
inbound peers, pending-Disconnect ordering, inbound slot reuse, successful
deadline clearing, stale token protection, non-reset of reconnect backoff on
TCP connect alone, partial pre-auth traffic without deadline extension, and
shutdown during `HelloPending`. They use monotonic synthetic deadlines and
bounded polling; no fixed sleep is used for correctness. Handshake expiry is
asserted as transport Unavailable/recovery only and never as peer-dead,
authority loss, promotion, demotion, lease mutation, resource operation, or
fencing evidence.
The automatic-reconnect clock regression also uses a future synthetic tick
and directly asserts `deadline == tick_now + HANDSHAKE_TIMEOUT`, with the
same-tick connection remaining in `HelloPending` until that deadline.
Transport-failure clock regressions likewise assert that handshake expiry
and synthetic-future Disconnect observation use the supplied tick time;
tests do not wait on or compare against wall-clock time.

### Stage 12.2 peer failure judgment tests

The Stage 12.2 tests cover the runtime-only `PeerFailureDetector` boundary.
They verify conservative startup as `Unobserved`, the requirement for a
current authenticated session plus a valid Fresh heartbeat before `Healthy`,
and the `Healthy → Suspect → CommunicationLost` transition at the finite
five-second caller-driven confirmation window. Synthetic monotonic times are
used; no sleep or wall-clock timing is a correctness mechanism.

They also verify that reconnect and HELLO establishment alone do not recover
the assessment, while a valid heartbeat for the new current session does;
old-session, replayed, wrong-identity, and otherwise invalid input cannot
clear a failure. Replacing a Healthy session enters a fresh Suspect episode,
while duplicate establishment of the same session preserves Healthy, the
sequence high-water, and the timer. The detector's runtime-only monotonic
time high-water rejects backwards heartbeat, session, and tick inputs before
state mutation; equal timestamps are accepted. Each flapping episode receives
a new timer, restart begins at `Unobserved` with no time high-water, and
snapshots do not advance the timer. These tests prove diagnostic communication
assessment only. They do not prove peer death,
automatic failover, promotion, demotion, lease or Witness mutation, fencing,
VIP/service operations, or resource uniqueness.

### Stage 12.3 Witness evidence fusion tests

The Stage 12.3 tests exercise the pure `EvidenceFusion` boundary with
caller-supplied monotonic `Instant` values and no sleep or background polling.
They cover startup `Unproven`, `Healthy` and `Unobserved` conservatism,
`Suspect` as `PeerDegraded`, fresh Witness corroboration for
`CommunicationLost`, and fresh `Unavailable`/`NotReady` as the conservative
`AmbiguousPartition` diagnostic. Unknown and expired Witness observations do
not corroborate and cannot remain sticky. Reachable, Unavailable, and NotReady
all use the same five-second timeout boundary; the tests cover expiry of both
Unavailable and NotReady and acceptance of a new fresh observation afterward.

The Stage 12.3 tests use synthetic issuance, not evidence of remote Reachable
integration. Token fields remain private with no public constructor; Stage 12.4
adds only adapter-owned local Unavailable issuance. Direct tests cover all four
statuses at exactly 5s and 5s + 1ns,
unchanged snapshot/time/generation after stale replay, and genuinely new evidence
after expiry. An adversarial Unavailable A/replayed A/new B/new Reachable C
timeline checks inclusive boundaries, older-token rejection and retention of the
replay watermark across peer recovery. Boot-change B replay cannot clear NotReady;
new C can. Missing/blank boot and foreign-runtime tokens are rejected. Delayed
delivery uses source time, and backwards/future source times do not mutate state.
These assertions establish bounded in-instance token replay protection and old
runtime token rejection, not cross-process or network replay protection. No
sleep, polling, authority action or persistent replay history is used.

The tests also cover peer recovery clearing fusion, Witness recovery changing
only evidence, boot-id change invalidating prior corroboration, bounded
holder/term observations, backwards-time rejection before mutation, equal
timestamps, read-only snapshots, and restart reset to `Unproven`. The fusion
API has no promotion, demotion, lease mutation, fencing, VIP/service, or
automatic-failover operation; those remain outside Stage 12.3.

### Stage 12.4 Witness adapter tests

Adapter tests use real loopback framed TCP for signed TERM_STATUS, HMAC failure,
semantic/malformed input, wrong cluster/sender/receiver/session/request ID, duplicate,
unsolicited and late response acceptance. The production nonblocking poll path has
a dedicated test using the existing bounded socket-readability helper (no sleep).
Other response tests use the same WitnessConnection validation and handler with
a blocking receive after sending the test response. Request and token times are
synthetic caller Instants. Terminal errors/EOF and receive transient errors are
injected at the private poll-result boundary; they are not real outage tests.

Assertions cover diagnostic-only TERM_STATUS without fake boot or Reachable token;
one timeout token at the inclusive request deadline; a second tick issuing nothing;
late A leaving B unchanged; terminal failure exactly once; NoFrame/transients keeping
pending state; 4s/6s delivery preserving source time; fusion rejection consuming the
token without replacement; increasing generations and overflow; request/deadline
overflow; single pending/delivery slots; restart namespace and origin rejection;
snapshot purity and backwards time rejection. The query-success then timeout
timeline reaches AmbiguousPartition only through local Unavailable evidence.
The forced request-id collision test binds an old authenticated response to its
original connection provenance and rejects it on a new connection; same-connection
success still passes. Correct request_id with wrong provenance and correct
provenance with wrong request_id are both rejected without pending or generation
mutation. This is a runtime connection-epoch boundary; persistent network replay
protection remains outside the scope.
Authority isolation is checked structurally: the adapter owns no authority/resource
backend and calls no lease mutation API; these tests do not simulate resource actions.
Remote Reachable/NotReady, multi-node HA and persistent replay guarantees remain
untested and deferred because they are outside the current-wire scope.

### Stage 12.5 failover eligibility policy tests

The Stage 12.5 policy tests are pure value-level tests with no clock, I/O,
Witness polling, lease calls, resource actions, or stored eligibility. They
cover conservative `CommunicationLost + CorroboratedLoss` eligibility only
from an explicitly `Safe` local readiness snapshot. `Standby` plus no
`OperationPhase` is insufficient by itself. The tests reject shutdown in
progress, blocked recovery, an independent demotion obligation, uncertain
ownership, unresolved resource/mutation state, present authority, unknown
local readiness, `Unobserved`, `Healthy`, `Suspect`, insufficient evidence,
and `AmbiguousPartition`.

The Linux runtime constructs the immutable local readiness boundary from the
existing daemon shutdown flag, current VIP/service observations, controller
recovery/demotion/ownership state, outstanding mutation state, and authority
presence. `Safe` requires current VIP `Absent` and service `Stopped` in
addition to `OwnershipClass::ZeroResource` and the other clear gates.
`ResourceOwning` and `Unknown` are distinct from `ZeroResource` and both fail
closed. Deterministic tests cover Present, Running, Unknown, post-reconcile
external drift, ownership Unknown, ownership ResourceOwning, and the clean
ZeroResource path. The runtime-boundary test
`live_authority_maps_to_runtime_blocker_and_blocks_failover_eligibility`
creates a real authority grant after zero-resource reconciliation while
leaving ownership, resources, mutation, and demotion state clean, then
asserts the exact `AuthorityPresent` readiness and non-Eligible policy result.
The snapshot is point-in-time; it is not a permanent
resource or authority proof, and a future action consumer must revalidate
before mutation. The policy consumes only that immutable value and remains
pure and stateless. This layer does not perform promotion or demotion, mutate
leases, operate VIP/service resources, perform fencing, or poll Witness;
availability-mode policy actions and live failover integration remain
deferred.

### Stage 12.6 promotion attempt authorization tests

`PromotionAttemptAuthorization` is tested as a pure, bounded, conservative
mode gate. Tests cover current Safe/Eligible authorization, ineligible and
indeterminate policy results, shutdown, authority presence, demotion latch,
resource drift, peer recovery, evidence expiry, active operations, restart
state, and `AmbiguousPartition`. Each case supplies current inputs again, so
an earlier `Eligible` value cannot authorize after local or peer state changes.
The module performs no lease, Witness, VIP, service, GARP, fencing, clock, or
disk operation. Stage 11 authority checkpoints and the future resource
promotion consumer remain outside this stage.

### Stage 12.7 observation foundation tests

The caller-driven GET_TERM foundation has seven direct tests on the
`WitnessEvidenceAdapter` observation lifecycle (`evidence_fusion::adapter`):
begin alone is pending until a correlated completion; only the current
authenticated and correlated TermStatus completion yields a current
observation; the completion acceptance time (not the poll time) is the fixed
freshness epoch; one request generation yields at most one `Ready` observation
(one-shot consumption) and a later poll of the same generation returns
`AwaitingWitnessTerm`; a stored previous completion cannot make a later
observation ready; a new `begin_observation_at` plus a new correlated
completion yields a second `Ready` observation; and a deadline poll reports
`Unavailable(Timeout)`, delivering the local Unavailable token to fusion once
with its source completion time, then leaving no `delivery_pending` and no
permanent `Busy`. A classified terminal read/reset error injected at the
documented private poll boundary is surfaced as `Unavailable(Transport)` and
drained in the first observation poll; an authentication rejection at the same
boundary is not normalized and remains fail-closed with the request still
pending. Real loopback TCP is used for the correlated-completion tests via the
existing bounded readability helper.

Coverage boundaries: wrong request IDs, wrong response kinds, duplicate and
unsolicited responses, connection-provenance mismatch, malformed input, and
restart namespace/origin rejection are covered by the existing Stage 12.4
tests and are reused through this lifecycle rather than re-tested at the 12.7
level. The daemon-side `LinuxDaemonRuntime` observation methods
(`attach_witness_observer`, `begin_authority_observation_at`,
`authority_observation_tick_at`) are caller-driven, have no callers, and are
therefore not exercised by these tests; the claim that peer assessment is
forwarded at the same observation time into the local safety snapshot is a
future composition requirement, not a verified behavior. `LinuxDaemonRuntime`
is `#[cfg(target_os = "linux")]` and is only type-checked cross-target here,
not executed. Evidence remains `Unproven` when the Stage 12.4 trust
requirements are not available. This stage performs no lease acquisition,
authority mutation, VIP, service, GARP, or fencing operation.

### Architecture Guard v1

Architecture Guard v1 is a deliberately small set of machine-checked invariants
that pin the observation/policy safety boundaries most likely to regress when a
future human or AI change is made. The guards use only `std`/Rust tests; there
is no new crate, no custom lint, and no CI-only tooling. They enforce a
specific invariant, not naming or vocabulary. They do **not** prove overall HA
safety, fencing behavior, or Linux runtime behavior.

- **MKM-ARCH-001** — Observation/policy modules (`evidence_fusion`,
  `witness_evidence_adapter`, `failover_policy`, `promotion_authorization`)
  must not depend on mutation-capable modules (`resource_executor`,
  `resource_workflow`, `linux_node_runtime`, `node_lease_authority`). Enforced
  by `tests/architecture.rs::mkm_arch_001_observation_and_policy_do_not_depend_on_mutation_layers`,
  which scans the protected source files for crate-path references (comments
  are stripped) and reports the offending `module -> crate::module` pair. A
  companion self-check (`mkm_arch_001_detector_catches_code_and_ignores_comments`)
  proves the detector catches a real dependency and ignores a path mentioned
  only in a comment, so the guard cannot pass trivially. Guarantee: an
  observation cannot reach the code that mutates authority, lease, VIP, or
  service.
- **MKM-ARCH-002** — Current term and freshness provenance. A stored
  `EvidenceFusion` term cannot make a new observation `Ready`; the current term
  comes only from the current correlated GET_TERM completion; `observed_at` is
  the completion acceptance time and a later poll cannot re-mint freshness.
  Enforced by
  `evidence_fusion::adapter::tests::mkm_arch_002_current_term_requires_current_completion_and_source_time`.
- **MKM-ARCH-003** — Failure classes never become `Ready`. Timeout, terminal
  transport, auth, semantic/protocol, wrong/stale correlation, wrong connection
  provenance, and duplicate completions must never produce `Ready`; only a
  valid authenticated correlated current GET_TERM TermStatus may. Enforced by
  `mkm_arch_003_failure_classes_never_produce_ready`, which includes a positive
  control so the guard is not vacuous.
- **MKM-ARCH-004** — One request generation yields at most one `Ready`.
  Repeated polling of generation N cannot produce another `Ready`; generation
  N+1 requires a new `begin` and a new correlated completion, then can produce
  its own `Ready`. Enforced by
  `mkm_arch_004_one_generation_yields_at_most_one_ready`.
- **MKM-ARCH-005** — Unavailable evidence exactly-once delivery. A completed
  `Unavailable` observation reaches `EvidenceFusion` exactly once with its
  original source time; it cannot be dropped, duplicated, overwritten by
  beginning another observation, or refreshed by repeated poll/drain. Enforced
  by `mkm_arch_005_unavailable_delivered_exactly_once_with_source_time`.

Each guard has no wall-clock dependence (all use caller-supplied synthetic
`Instant`s) and is deterministic.

### Stage 12.8a current-term / stored-evidence type hardening tests

Stage 12.8a adds deterministic tests for the current-term / stored-evidence
separation (not a new Architecture Guard):

- `current_witness_term_is_minted_from_correlated_completion` — a valid
  authenticated, correlated current GET_TERM completion produces a
  `CurrentWitnessTerm` whose `term()` is the completion term and whose
  `observed_at()` is the completion acceptance time.
- `stored_witness_term_cannot_mint_current_witness_term_or_ready` — a planted
  `EvidenceFusionSnapshot::witness_term` cannot by itself produce a
  `CurrentWitnessTerm` or a `Ready` observation; a fresh completion yields the
  completion's own term, not the stored one.
- `witness_evidence_view_excludes_historical_term_and_holder` — the derived
  `WitnessEvidenceView` excludes `witness_term` and `witness_holder` while the
  snapshot retains them for status. The absence is guaranteed structurally by
  the view's type definition, so no source grep is used.

The MKM-ARCH-001 through MKM-ARCH-005 guards continue to pass unchanged. The
`CurrentWitnessTerm` newtype has private fields, no public constructor, no
`From`/`Into` from `EvidenceFusionSnapshot`, and is neither `Clone`/`Copy` nor
serializable/persistable. This stage implements type/API hardening only; it does
not implement daemon clock composition (H-2), shutdown composition, or
observation-to-policy wiring, and it performs no Linux runtime execution.
Cross-target `cargo check` type-checks the Linux-only `#[cfg]` code but is not
Linux runtime validation.

### Stage 12.8b single observation clock tests

Stage 12.8b resolves H-2 with a deterministic composition and adds **MKM-ARCH-006**:

> One daemon observation iteration uses one authoritative observation time and
> advances the peer runtime at most once.

Enforced behaviorally (not by source grep) with the `FakeRuntime` test double,
which records the `now` used for each peer advance and each peer snapshot:

- `mkm_arch_006_one_iteration_uses_supplied_time_and_advances_peer_once` — a
  single `Daemon::tick_at(T)` advances the peer exactly once with `T` and snapshots
  it with the same `T`.
- `mkm_arch_006_two_iterations_advance_once_each_with_their_own_time` — two
  iterations advance exactly once each, with `T1` then `T2`.
- `mkm_arch_006_tick_at_does_not_sample_internal_clock` — a far-future supplied
  `T` is the value the peer progression observes; no internal `Instant::now()`
  enters the `tick_at` path.
- `mkm_arch_006_peer_time_failure_is_fail_closed` — a failing peer advance latches
  `Unavailable` for the iteration and does not fabricate a healthy observation.
- `mkm_arch_006_peer_and_witness_evidence_are_independent` (value boundary in
  `evidence_fusion`) — a Witness observation cannot fabricate healthy peer
  evidence, and a peer assessment cannot change independent Witness status/term.

The existing `Daemon::tick()` remains a convenience wrapper sampling
`Instant::now()` once and delegating to `tick_at`. Earlier daemon tests that used
`daemon.tick()` are unchanged and still pass.

Scope: this stage does not implement shutdown composition (Stage 12.8c),
observation-to-eligibility wiring (Stage 12.8d), or any promotion/lease/resource
mutation. **No Linux runtime execution has occurred.** Cross-target
`cargo check --target x86_64-unknown-linux-gnu` only type-checks the Linux-only
`#[cfg]` code and is not Linux runtime validation. The authority/lease
`SystemMonotonicClock` domain is unchanged.

### Stage 12.8c shutdown ownership tests

Stage 12.8c adds **MKM-ARCH-007**:

> Shutdown-in-progress cannot produce promotion-safe local readiness.

The raw `shutdown_requested: bool` hazard is removed at compile time: the
authority observation API accepts only `DaemonIterationContext`, whose fields are
private and whose only production constructor is `Daemon::iteration_context`
(from Daemon-owned state). There is no overload taking a raw bool, so a call
that substitutes a literal `false` while the Daemon is shutting down no longer
compiles. The tests therefore prove the behavioral boundary rather than parsing
Rust source:

- `mkm_arch_007_iteration_context_tracks_daemon_shutdown_ownership` — before
  `request_shutdown()` the context reports `false`; after it reports `true`; and
  the context uses exactly the supplied `Daemon::tick_at(T)` time without
  sampling a second `Instant`.
- `mkm_arch_007_shutdown_local_safety_is_never_eligible_or_authorized` — with a
  positive control (`CommunicationLost + CorroboratedLoss + Safe` is
  Eligible/Authorized before shutdown), the same strongest evidence after
  shutdown yields `ShutdownInProgress`, non-`Eligible`, and non-`Authorized`.
- `mkm_arch_007_ready_evidence_cannot_override_shutdown_blocking` — a Ready-
  equivalent strongest evidence value cannot turn shutdown local safety into
  promotion permission.

Shutdown/demotion remains independent of peer/Witness availability and is
unchanged (existing `attack_*` shutdown tests still pass). MKM-ARCH-001 through
MKM-ARCH-006 remain green, and Stage 12.8a type-hardening tests remain green.

Scope: this stage does not implement Stage 12.8d production observation->policy
wiring, any promotion/lease/resource mutation, or Linux CI. **No Linux runtime
execution has occurred.** Cross-target `cargo check --target
x86_64-unknown-linux-gnu` is not Linux runtime validation.

### Stage 12.8d inert decision composition tests

Stage 12.8d adds **MKM-ARCH-008**:

> Authority observation / eligibility / authorization composition is inert and
> cannot directly perform promotion or resource mutation.

The production composition (Linux-only) progresses the current Witness
observation and produces `AuthorityAttemptEvaluation` only for a current `Ready`
term. `AuthorityObservationProgress::into_evaluation` and
`AuthorityAttemptEvaluation::evaluate` are cross-platform and tested
deterministically on macOS:

- `mkm_arch_008_evaluation_is_inert_and_idempotent` — the strongest evidence and
  a `Safe` local boundary can yield Eligible/Authorized as inert data; repeated
  evaluation is stable and exposes no mutation capability.
- `mkm_arch_008_healthy_peer_never_authorizes` — healthy peer + valid current
  term + `Safe` local is neither Eligible nor Authorized.
- `mkm_arch_008_insufficient_evidence_fails_closed` — `Unproven`, `PeerDegraded`,
  and `AmbiguousPartition` never authorize.
- `mkm_arch_008_shutdown_blocks_authorization` — strongest evidence with
  `ShutdownInProgress` local is never Eligible/Authorized.
- `mkm_arch_008_ready_does_not_imply_eligible_or_authorized` — `Ready` is a
  distinct stage: it carries the current term but authorizes nothing.
- `mkm_arch_008_pending_and_unavailable_never_produce_an_attempt` — `Awaiting`
  and `Unavailable(Timeout|Transport)` map to no attempt (`None`), never a
  manufactured term.

Scenario coverage (deterministic, macOS): A healthy peer + Ready -> non-Eligible;
B communication lost + insufficient evidence -> fail closed; C corroborated loss
+ safe local + valid current term -> Eligible/Authorized as inert data only; D
strong evidence + shutdown -> non-Eligible/non-Authorized; E Witness Unavailable
-> no attempt; F stale/invalid/wrong-provenance never Ready (Stage 12.4/12.7
paths) -> no attempt; G backwards time fails closed (adapter/fusion guards).

`AuthorityAttemptEvaluation` has no handle to an authority/resource owner and no
action method; MKM-ARCH-001 continues to keep the observation/policy modules
free of mutation-layer dependencies. **No mutation wiring exists** (no promotion,
lease, VIP/service/GARP, Active commit), and **no Linux runtime execution has
occurred**; cross-target `cargo check` is not Linux runtime validation.

### Stage 12.8e deterministic failover scenario matrix tests

Stage 12.8e adds **MKM-ARCH-009**:

> Failover decision scenario matrix is fail-closed across ambiguous, stale,
> unavailable, shutdown, and timing-failure inputs.

`mkm_arch_009_failover_scenario_matrix_is_fail_closed` is table-driven over a
`MatrixRow` harness, asserting observation presence, eligibility, authorization,
peer/readiness preservation, and zero mutation-sentinel calls per row. It
requires a positive `Authorized` control, so the guard is not vacuous.

Matrix (deterministic, cross-platform):

| Scenario | Observation | Eligible | Authorized | Mutation |
|---|---|---|---|---|
| A healthy peer + Ready | Ready | no | no | no |
| B comm-lost + Unproven | Ready | no | no | no |
| B2 comm-lost + PeerDegraded | Ready | no | no | no |
| C **comm-lost + CorroboratedLoss + Safe (positive control)** | Ready | **yes** | **yes** | no |
| D strong evidence + shutdown | Ready | no | no | no |
| E witness Unavailable(Transport) | none | no | no | no |
| F witness Awaiting | none | no | no | no |
| M witness terminal + healthy peer | none | no | no | no |
| N Ready + AmbiguousPartition | Ready | no | no | no |
| L peer comm-lost + corroborated loss (independent) | Ready | yes | yes | no |

Additional scenarios proven by existing guards and new sequence tests:
G no Witness adapter (Linux-only production `evaluate_authority_attempt`,
deferred to 12.8f; absence modelled as no attempt); H historical
`witness_term` only -> no current term (Stage 12.8a); I wrong request
generation -> no Ready (Stage 12.4/12.7); J wrong observation generation -> no
Ready; K time moves backwards -> fail closed (adapter/fusion guards).

Sequences (deterministic):
- `stage_12_8e_seq_1_healthy_to_corroborated_loss` (healthy -> comm-lost/unproven
  -> corroborated loss; only the last is Authorized).
- `stage_12_8e_seq_2_ready_then_shutdown_cannot_override` (Ready term Authorized,
  then shutdown blocks it; Ready cannot override).
- `stage_12_8e_seq_1_and_2_never_tick_peer_or_mutate` (pure evaluation does not
  advance the peer runtime or call promote).
- `stage_12_8e_seq_3_superseded_generation_cannot_authorize` (late generation-1
  completion rejected for generation 2).
- `stage_12_8e_seq_4_unavailable_then_fresh_ready_is_independent` (exactly-once
  Unavailable; a later fresh generation independently becomes Ready; local
  Unavailable evidence is not reused or cleared by a diagnostic success).

Mutation sentinel: the matrix carries a test-only `MutationSentinel` with
`promotion_calls`/`lease_mutation_calls`/`resource_mutation_calls`, all asserted
zero. The evaluation types hold no handle that could reach it; this proves the
tested cross-platform composition is mutation-free, not that the Linux runtime
is.

**No mutation wiring exists**, and **no Linux runtime execution has occurred**.
Cross-target `cargo check` is not Linux runtime validation; Stage 12.8f covers
Linux execution. Stage 12.8 is not complete.

### Stage 12.8f Linux runtime validation tests

Stage 12.8f adds **MKM-ARCH-010** (Linux-only, `#[cfg(all(test, target_os = "linux"))]`
in `daemon::linux_composition_tests`):

> Linux authority-decision composition remains inert and fail-closed.

- `mkm_arch_010_no_witness_adapter_fails_closed` — real `LinuxDaemonRuntime`
  with no Witness adapter: `evaluate_authority_attempt` returns `Err`; no
  Authorized attempt, no mutation.
- `mkm_arch_010_no_current_term_fails_closed` — real adapter, begun GET_TERM with
  no completion: `AwaitingWitnessTerm`, `into_evaluation()` is `None`,
  `evaluate_authority_attempt` is `None`; zero peer advances.
- `mkm_arch_010_shutdown_fails_closed_and_single_peer_advance` — real
  `LinuxDaemonRuntime` with a connectionless peer: one `peer_tick_at` advances
  the peer exactly once; a second advances once more (no hidden extra); a
  shutdown context yields `ShutdownInProgress` and no attempt, and evaluation
  does not advance the peer.
- `mkm_arch_010_ready_is_not_authorized_on_real_linux_composition` — a real
  correlated `TERM_STATUS` over a loopback Witness socket mints a current term
  (term 7) through the production correlation path; the real composition yields
  `Ready` but **non-Authorized**, proving `Ready != Authorized` on Linux and
  zero peer advance.

Environment (actual Linux execution): Ubuntu 24.04.3 LTS, aarch64, Rust 1.98.0,
non-root (uid 501), inside a Lima/VZ VM; no root and no host
VIP/service/GARP/network mutation. The tests use a `#[cfg(test)]`-only
`LinuxDaemonRuntime::new_for_test` because the production `from_config` loads a
root-owned PSK file; the production PSK path is not exercised. Mutation absence
is directly proven (no promotion/lease/VIP/service/GARP reachable from the
evaluation; zero peer advances), structurally prevented by ARCH-001, and
deferred for real mutation success to a later promotion/resource E2E stage.

**Linux runtime execution has now occurred for the inert decision composition.**
Successful real systemd/VIP/GARP mutation remains unvalidated and is out of
scope. Cross-target `cargo check` is not a substitute for this execution.

### Stage 13.1 promotion attempt lifecycle tests

Stage 13.1 adds **MKM-ARCH-011**:

> Promotion attempt lifecycle is inert and overlapping attempts are forbidden.

Deterministic, cross-platform (`daemon::tests`):

- `mkm_arch_011_accepting_request_is_inert_and_non_overlapping` — a fresh
  request is accepted while idle (positive control); a second and a duplicate
  request are rejected as already-in-progress without changing the in-flight
  identity; acceptance performs no promotion call and zero peer advances.
- `mkm_arch_011_finish_and_cancel_return_to_idle` — completing or cancelling
  returns the slot to idle and a later fresh request can be accepted; completing
  or cancelling an idle slot is a no-op.
- `mkm_arch_011_shutdown_blocks_new_acceptance` — after `request_shutdown()`, a
  new attempt is rejected (`RejectedShutdown`) and the slot stays idle.

The lifecycle state (`PromotionAttemptLifecycle`) stores only the in-flight
`PromotionRequestId`; it has no field capable of holding an
`AuthorityAttemptEvaluation`, `CurrentWitnessTerm`, lease authority, permission,
resource handle, or callback, so property G is enforced structurally rather
than by source scanning. Accepting a request performs zero authority/resource
mutation, and `Authorized` is never stored. MKM-ARCH-001 through MKM-ARCH-010
remain green. Stage 13.2 remains responsible for fresh revalidation + lease
handoff; no mutation wiring exists.

### Stage 13.2-pre single Witness session ownership tests

Stage 13.2-pre adds **MKM-ARCH-012-PRE**:

> Daemon Witness observation uses one neutral session owner and one outstanding
> request slot.

Ownership is enforced structurally by the type system: `WitnessEvidenceAdapter::new`
takes no `WitnessConnection`, `ProcessSession`, or `MessageAuthenticator`, and
the adapter stores none of them nor a `WitnessRequestOutstanding`. The
behavioral tests:

- `mkm_arch_012_pre_get_term_succeeds_through_borrowed_session` — positive
  control: a real GET_TERM request flows through the borrowed `WitnessSession`
  and correlates to a `Ready` current term.
- `mkm_arch_012_pre_second_request_cannot_bypass_shared_outstanding` — a second
  observation request through the same session fails with
  `RequestAlreadyOutstanding`, proving one shared slot.

All existing `WitnessEvidenceAdapter` tests were adapted to construct the
`(session, adapter)` pair (the production composition shape) while preserving
their assertions. Existing Stage 12.8 guards (ARCH-001 through ARCH-011) remain
green. No lease wiring, no reconnect, and production `Authorized` remains
unreachable. No Linux runtime execution is required for this refactor;
cross-target `cargo check` type-checks the Linux-only composition.

### Stage 13.2 tests / MKM-ARCH-012

Stage 13.2 adds **MKM-ARCH-012**. Stage 13.2-pre remains **MKM-ARCH-012-PRE** and is not renamed or blurred into MKM-ARCH-012.

Architecture property:

> A promotion attempt can cross into mutation only after fresh revalidation and fresh attempt-bound lease authority through the single shared Witness session.

Named tests (deterministic; cross-platform unless marked Linux-only):

1. `mkm_arch_012_positive_control_reaches_stage_13_2_success_boundary`
   Fresh InFlight attempt -> fresh revalidation -> fresh Authorized -> shared-session lease AcceptedSuccess -> final checkpoint -> intended Stage 13.2 success boundary (Stage 11 handoff / `Succeeded` under test doubles). Proves the implementation does not pass by rejecting everything.

2. `mkm_arch_012_inflight_alone_is_not_authority`
   InFlight without fresh Authorized cannot reach mutation.

3. `mkm_arch_012_stale_authorization_is_not_reused`
   An older/stored `Authorized` or prior evaluation cannot authorize a later attempt. Only the current `evaluate_authority_attempt` result counts.

4. `mkm_arch_012_preexisting_inflight_with_shutdown_cannot_execute`
   Attempt exists, then `request_shutdown()`; execution/mutation does not occur.

5. `mkm_arch_012_shutdown_after_revalidation_cannot_execute`
   Fresh Authorized then shutdown; no mutation; lease not handed to Stage 11.

6. `mkm_arch_012_lease_failure_blocks_mutation`
   Authorized without lease `AcceptedSuccess` cannot execute.

7. `mkm_arch_012_wrong_attempt_cannot_use_other_attempt_authority`
   Authority/lease bound to attempt A cannot execute attempt B.

8. `mkm_arch_012_retired_id_reuse_does_not_recover_authority`
   Reusing a retired `PromotionRequestId` creates only a new inert attempt path and cannot recover old authorization or lease.

9. `mkm_arch_012_single_observation_owner_no_double_poll`
   One execution revalidation does not call `authority_observation_tick` then `evaluate_authority_attempt` for the same logical observation; peer advances stay at the expected count.

10. `mkm_arch_012_shared_witness_outstanding_slot_is_enforced`
    Observation and lease operations cannot bypass the shared `WitnessSession` slot; a second concurrent outstanding request is rejected.

11. `mkm_arch_012_cancelled_attempt_cannot_execute_on_late_response`
    Cancel/retire before mutation; a later lease/auth response cannot execute.

12. `mkm_arch_012_mutation_failure_uses_stage_11_rollback`
    If Stage 11 promotion is entered and fails, existing rollback/cleanup semantics apply and success is not reported (`MutationFailed`).

13. `mkm_arch_012_lease_cleanup_on_abort_cannot_leak_authority`
    Abort after lease acquisition follows the documented release/expiry contract and cannot leave executable authority.

Observability for negative tests (assert where applicable):

- `promotion_calls == 0`
- `resource_mutations == 0`
- `wrong_attempt_retirements == 0`
- `unexpected_peer_advances == 0`
- second shared-session outstanding request rejected

These assert externally meaningful safety properties and do not freeze internal refactoring.

Coverage boundaries: Stage 13.2 tests do not prove real systemd/VIP/GARP success, fencing, automatic failover, or multi-node split-brain freedom. Stage 11 resource tests remain authoritative for mutation internals. MKM-ARCH-001 through MKM-ARCH-011 and MKM-ARCH-012-PRE must remain green.

Architecture Guard note: `promotion_attempt` remains protected and inert. If a narrow orchestration module is introduced (for example `promotion_execution` in `daemon` or a dedicated `promotion_execution` module), it may depend on decision and mutation layers only as required to drive one attempt; ARCH-001 must not be broadly weakened. Policy modules (`failover_policy`, `promotion_authorization`, `evidence_fusion`, `witness_evidence_adapter`) stay mutation-free. `promotion_attempt` must not import mutation-layer modules.

### Stage 13.3 tests / MKM-ARCH-013 (remediated)

Architecture property:

> Fresh local communication-loss evidence plus real authenticated/correlated
> TermStatus with `AuthorityViewCompatible` can reach
> `FailoverEvidenceReady` and `Authorized`; transport success alone cannot,
> and stale local loss cannot pair with fresh Witness evidence.

Positive control (`mkm_arch_013_*`): real protocol encode/decode + HMAC +
request correlation + `WitnessSession` + production evidence adapter +
fusion + authorization. Must **not** directly construct the final evidence
state (`Reachable` / `AuthorityViewCompatible` / `FailoverEvidenceReady`).

Required negatives:

1. transport success alone cannot authorize
2. holder None + healthy peer cannot authorize
3. stale CommLost + fresh TermStatus cannot authorize
4. fresh CommLost + stale TermStatus cannot authorize
5. Self + remaining=0 cannot authorize
6. Foreign + remaining>0 cannot authorize
7. Foreign + remaining=0 cannot authorize
8. wrong term cannot authorize
9. replay cannot authorize
10. auth failure cannot authorize
11. correlation failure cannot authorize
12. peer recovery invalidates local loss
13. local restart invalidates local evidence
14. term movement invalidates both axes
15. Witness unavailable cannot authorize
16. outstanding conflict cannot authorize
17. shutdown cannot authorize
18. no cached Authorized
19. no evidence reuse across attempts
20. no lease acquisition from Stage 13.3
21. no resource mutation from Stage 13.3
22. no CLI promotion
23. no automatic failover
24. one logical observation owner
25. one shared Witness outstanding slot

Direct semantic test:

- GET_TERM `Some(holder) + remaining=0` is classified
  `ExpiredButUnprocessed` and is **not** silently treated as `None`.

MKM-ARCH-010/011/012 remain green. Stage 13.3 is non-mutating and adds no
promotion caller.

## v1.0 の追加テスト（Hostで実行したもの／実行していないもの）

- **Host（macOS）で実行**: 設定スキーマ（拒否キー・方向規則・既定値・同梱例の解析）、Witnessサーバー（実TCPのgrant/renew/release、HELLO期限、接続数、二重起動拒否、再武装各種）、`command`サービス（実プロセス：信頼検査、プロセスグループkill、`status`文法、`start`後のstopped不信）、Bootstrap Admission（純関数の決定、peer往復、Daemon全体の2回試行・各block経路・段ごとの抑止）、Witness側のCAS競合（anchor前後・全周期後）、SOR（decide・store操作・exact release・保持されたRelease再実行）、自動トリガー（前提条件・dwell・予算・間隔・サイクル数・FAILED停止・bootstrapの優先/待機・hygiene）、health hysteresis、遷移ログ、Witness接続喪失時の終了、`recovery_gate`の原因文、同梱systemdユニットの`ExecStart`解析。
- **Stage 15 独立監査の修復（F15-M1〜M4、L1、L2）で追加**: commandサービスの清掃責任（`KILL`失敗・グループ残存・census不確定・nonblocking設定失敗の各分岐、故障注入。破壊的シグナルは常にリーダー未回収中だけ）、手動SIGUSR1とautoの同時pendingの同時消費、手動BA sessionの5秒/60秒/Safe・Healthy喪失の衛生（`[failover] auto`の有無によらない）、`plain_arm_gate`の全エラー網羅、BG-12の制御構造検査と14種のbypass mutationの自己検査、Witness serverの委譲検査と11種のmutation自己検査。
- **Stage 15 FH-1 / FH-2 限定修復で追加（Host）**: systemdバックエンドの有界化（子の終了後も書き込み側が残る・EOFが来ない・期限直前/直後のEOF・killの失敗・waitの失敗・出力上限超過・I/Oエラー・繰り返しtimeoutでのFD非蓄積・遅延writerの非干渉。実プロセスと偽pipeの両方）、`SIGCHLD`拒否の6ケース（未完了清掃なし／あり／完了後／失敗後／pin喪失後／Default復帰。既存清掃のシグナルと新規子のシグナルを区別）、`Runner::run`の順序と`systemd_service`の単一スレッド性のarchitectureガード。Linux上の実行は含まない。
- **実行していない（Linux専用コード、または別ホストが必要）**: `linux_node_runtime`配下の全テスト（`cfg(target_os = "linux")`）、`LinuxDaemonRuntime`のBA/SOR/自動トリガー配線、実`systemd`、実VIP/GARP、実fence、VM再起動による実boot id変化、Linux labのclose-out。これらは型検査（`cargo check --tests --target x86_64-unknown-linux-gnu`）のみ。

## GCE の実機検証環境の運用（使用後削除。2026-11-18 Owner の方針）

v0.7 の U1 / U2 の実機受入で使った運用（run 単位の作成、証拠の封印、P-4 による削除）を、以後の GCE の検証の標準とする。新しい cleanup の機構は作らず、既存の駆動部（`tools/mikagami-u1`、`tools/mikagami-u2`。repo 外）と P-4 の script・契約を使う。

1. **作成の単位**：試験に要る VM、disk、network、subnet、firewall、service account、custom role、IAM binding、budget は、run ごとに作る。名前は run の接頭辞（例 `mkg-f5rNN-*`、role は `mkgF5rNN*`）で識別でき、駆動部の state に記録されたものだけを run の資源とする。駆動部の書込みの一覧（OPSPEC と段ごとの allowlist）に無い種類（snapshot、静的 IP、追加の disk、image など）は作らない。
2. **証拠の封印**：試験の終わりに、必要な log と証拠を外付けの証拠の dir に保存し、`verify-poststate`、`seal-run`（MANIFEST）、`export-redacted` の順に封印する。封印の前に資源を消さない。
3. **P-4 cleanup**：封印の後、その run の P-4 を行う。手順は plan → execute → verify。対象は、その run_id の state に記録され、かつ run の接頭辞に一致する資源だけ。他の所有者の VM、disk、network、IAM、budget、既存の資源には触れない。P-4 には Owner の承認が要る（承認の範囲と run_id を承認の記録に書く）。
4. **停止で放置しない**：費用を減らす目的で、止めた VM や disk を残さない。止めたまま残すのは、封印から P-4 までの間だけとする。
5. **残存 0 の確認**：P-4 の verify で、その run の instance、disk、firewall、service account、binding、active な role が 0、network、subnet、budget が無いことを確かめる。snapshot と静的 IP は、封印の前の `verify-poststate`（ST-3 の分類。run の想定は 0 件で、Mikagami の名前のものや run の disk の snapshot があれば NG）で 0 を確かめる。v0.7 の P-4 の verify はこの 2 種を数えないが、駆動部と P-4 はこの 2 種を作れない（書込みの一覧に無い）ので、`verify-poststate` の OK の後に増えることは無い。次の run からは、P-4 の verify にも接頭辞の snapshot と静的 IP の読み取りを加え、結果に含める。削除済みの custom role は IAM の保持期間の後に自動で消え、費用はかからない。
6. **削除の失敗**：削除できなかった資源があれば、対象（種類と名前の接頭辞）、失敗の理由（命令の rc と応答の要約）、継続課金の見積り（1 時間あたり、日あたり）を報告し、再試行は Owner の判断を待つ。自動の再試行はしない。
7. **費用と停止の条件**：段ごとの費用の上限と ST-2、FAIL / INCONCLUSIVE / UNKNOWN での停止、once-only の書込みの規則は変えない。
