# Safety Model

> 開発者向けの設計・検証の記録です。開発の工程の識別子（段階や判断の番号）と、公開候補に含まれない内部の資料への参照を含みます。利用の手順は [`README.md`](../README.md) と [`configuration.md`](configuration.md) を参照してください。

## Core distinctions

- heartbeat lossはpeer deathを意味しない
- Witnessはfencingではない
- leaseはfencingではない
- termはfencing tokenではない
- VIP ownershipはクラスタ全体での唯一性の証明ではない

fencingなしでは、旧Activeが停止したこと、またはサービスとVIPを解放したことを保証できない。

Recovery Transaction Contract v1.1では、一つのcanonical pathについてrecovery inspection、canonical snapshot取得、canonical persistenceを同じprocess-global transaction lockで直列化する。uncertain pathは全handleのnormal read、write、begin、completion、Witness save、scheduler mutation、authoritative GET_TERMをfail closedにする。Recovery Metadata v1のオンディスク形式は変更しない。v1.2では、lock identityと実際のfilesystem I/O targetを同じResolvedStorePathから導出し、candidate由来snapshotのExpectedOldTokenをwrite boundaryまで必須にする。これらは実装済みで、決定的な直接テストで検証している。なお、実電源断など未検証の境界は別途明示する。

PREPAREはhard-linkによるno-replace installで既存markerを上書きしない。marker temporary、candidate temporaryはauthority evidenceではなく、transaction-unique nameとcreate_newで扱う。NEW fingerprintはdurability proofではなく、canonical parent fsync後のconfirmed commitだけがdurability境界である。

authority uncertaintyはlocal relinquishmentを禁止しない。`Active → QuorumUnknown → local demotion`は有効な安全経路であり、Witness、lease renewal、peer acknowledgement、authority reacquisitionを待たずに既存のservice停止・VIP解放順序を開始する。これはpromotion authorityを与えず、fencingやcleanup完了の証明にもならない。

永続化ではcanonical pathnameの可視性をdurabilityの証明に使用しない。Recovery Metadata v1のdurable PREPARE確認前にcanonical stateを変更してはならない。canonical namespace変更後に必要なdirectory fsyncが失敗した場合は`CommitOutcomeUnknown`とし、旧state・新stateのいずれも確定authorityと推測しない。markerが残る間、Nodeは新generation／sendを、Witnessはauthority mutation／success response／authoritative GET_TERMを停止する。

versionless legacy Witness stateは通常loadで自動移行せず、bytesを変更しない`MigrationRequired`/NotReadyとする。明示的migrationだけがF-01.1 transactionを使用して移行でき、移行途中のmarker cleanupが不確定ならRecoveryRequiredとしてfail closedにする。

## Modes

`conservative`はfail-closedを基本とする。Witnessなしの自動promotionとforce failoverは禁止する。peer停止やcleanup完了を証明できない場合、自動promotionしない。

`availability`は明示的にunsafeなモードである。force failoverを許可できるが、旧ActiveがサービスやVIPを保持したままの場合、二重Activeや二重稼働が発生し得る。

## Resource cleanup

demotionでは、サービス停止確認後にVIPを解放し、VIP解放確認後にStandbyへ遷移する。

- systemd：stop要求成功だけでなく`inactive`を確認する。`systemctl`の実行はtimeoutに回収予算を加えた範囲で有界であり、子のreapを確認できない間は新しいコマンドを起動しない。出力が完全に読めた（EOF・上限内）場合だけ`systemctl show`の結果を使う
- command：旧契約ではstopのexit code 0とhealth check非正常を停止確認として扱っていたが、Stage 11.3で安全上訂正する。これはreadiness非正常を示すだけで、process/service ownershipの不在、ConfirmedStopped、ZeroResourceを証明しない。trustedな停止観測手段がない場合はService Unknownのままとする
- commandのstop確認ができない場合は、固定された`StopService → ConfirmServiceStopped`順序に従い、VIP解放やStandbyへ進まない
- 必要なtrusted postconditionを確認できない場合はcleanup確認失敗として`Failed`にする。actionのtimeout/errorだけではcleanup失敗を確定しない。timeout/error後にtrustedなService StoppedまたはVIP Absentを確認できた場合は、そのresource truthを保持し、固定された順序で許可される次のcleanupへ進む
- cleanup未確認時は自動promotionしない

## Lease loss

Activeがleaseを更新できない場合、safety marginを差し引いて算出したNode側local expiryに到達した時点で直ちにdemotionを開始する。service停止とVIP解放の完了は別途確認する。

lease safety marginのdefaultは2秒である。これはNodeがWitness側lease expiryより前に自己demotionを開始するための保守的な安全窓であり、demotion完了を保証する値ではない。fencingの代替でも、二重Active防止を保証する値でもない。

lease安全判定にwall clockは使用しない。WitnessとNodeはそれぞれmonotonic clockを使用し、絶対時刻の同期を前提にしない。

## Partial failures

Mikagamiプロセスだけが停止すると、管理対象サービスとVIPが残る可能性がある。Witness leaseの期限切れだけでは、それらの解放を証明できない。

OS hang、電源断、kernel停止、scheduler pauseでは自己demotionやcleanupが実行されない可能性がある。したがって、fencingなしでは旧Active停止を保証できない。

heartbeatの`Unreachable`はlocal nodeからpeer communicationを設定時間以上観測できないという意味だけであり、peer deathを証明しない。`Unreachable`だけではpromotionを許可しない。

起動直後など、まだ有効なheartbeat成功観測がない状態は`NotObservedYet`であり、`Healthy`とはみなさない。これはpeerが生存・停止のいずれであるかを証明しない。liveness観測はpromotion authorityではない。

raw TCP activity、frame受信、decode、認証、またはprotocol validationだけではliveness successではない。期待するpeerのHEARTBEAT/HEARTBEAT_ACKが受理され、peer sequence high-waterへcommitされた場合だけlast-success observationを更新する。この観測もpromotion authorityではない。

established messageのdispatcherが返すPending messageは、認証済み・共通peer検証済み・replay-freshであることだけを示し、authorityや副作用の開始を示さない。handlerのsemantic acceptanceとhigh-water commit前に、NodeState変更やpromotion/demotion等の副作用を開始しない。

HEARTBEATの送信成功だけではliveness successではなく、ACKを受理・commitした時点で初めてpeer観測を更新する。unsolicited ACKは受理しない。ACK commit後のlocal tracker errorでもsequenceをrollbackせず、heartbeat観測はauthorityにならない。

runtime routingだけではauthorityを増やさない。未処理のnon-heartbeat Pendingはhandlerのsemantic acceptanceとpeer high-water commit前の観測に限られる。現在のpeer runtimeはState/Promotion/Demotion messageも専用handlerへ内部routingするが、accepted resultやcommunication-level ACKはauthority、resource cleanup、lease解放を意味しない。runtime errorはpeer deathへの変換やtrackerのclear、outstandingの無条件reset、connectionの自動dropを行わない。unrelated messageを受信してもAwaitingAckは維持する。

STATE_ANNOUNCEで受信したpeerのNodeStatus、term、lease_id、service/VIP状態は観測値にすぎず、local NodeState、authority、promotion/demotion判断を変更しない。STATE_ANNOUNCE_ACKもpromotion許可やownershipの証明ではない。STATE_ANNOUNCE/ACKはheartbeat livenessを更新しない。STATE_ANNOUNCEはhigh-water commit後にACKを送信し、STATE_ANNOUNCE_ACKは独立したoutstandingを確認してからcommit・完了する。

PROMOTION_INTENTとPROMOTION_ACK/BLOCK/UNKNOWNもpeer coordinationの観測・応答に限られる。`PROMOTION_ACK != promotion authority`であり、これらのmessageはNodeState、OperationPhase、term、lease、liveness、VIP、serviceまたはfencingを変更しない。responseはoutstandingとoperation_idを確認してからcommitし、unsolicitedまたは異なるoperation_idはcommit前に拒否する。

## Known split-brain cases

- Node間だけのネットワーク分断（v0.7：旧ActiveがWitnessのleaseを保つ間は、Standbyの側は`partition ambiguous`で止まり、fencingのincidentを開かない。自動の切替は旧ActiveがWitnessからも切れた場合に限る）
- ActiveとWitness間だけの通信断
- Witness停止
- Mikagamiだけのkill
- OS hangや電源断
- promotion/demotion途中のプロセス停止
- service停止確認失敗
- VIP解放失敗
- 両Nodeからのforce操作
- availabilityモードでの自動promotion

## Guarantees

`DEMOTION_ACK != demotion completion proof`である。`DEMOTION_COMMITTED`の`service_stopped`および`vip_released`もpeer-reported observationにすぎず、lease release、fencing、promotion permissionまたはliveness proofではない。Demotion messageはNodeState、OperationPhase、liveness、HeartbeatOutstanding、PromotionOutstandingを変更しない。

Witness Runtime Stage 1では、authenticated Witness messageはauthoritative decisionではなく、correlated Witness responseもlocally accepted lease/termではない。request/responseのsemantic acceptanceとreplay commitだけを行い、term/lease state、NodeState、OperationPhase、liveness、promotion permission、fencingを変更しない。Witness persistenceとauthorityは後工程である。

Witness Runtime Stage 2では、process restartとOS rebootを区別する。persisted `boot_id`と現在の`boot_id`が一致する場合だけmonotonic deadlineを同一domainとして復元できる。boot_id不一致、missing/corrupt/inconsistent state、または永続化失敗はfail-closedでNotReadyとし、termを0へresetしたり旧leaseを推測でclearしたりしない。durable save成功前にauthority successを返す統合は後工程で行う。

Witness Runtime Stage 3の`GET_TERM`はtermをincrementせず、leaseを変更せず、durable stateを更新しない。valid requestのreplay high-water commitとTERM_STATUS response成功は別であり、NotReady、Unknown、clock failure、response送信失敗でもrequest commitやstateをrollbackしない。Active leaseのremainingが0でもStage 3ではexpiry transitionを行わない。

Stage 3.9で固定した`LEASE_REQUEST` policyでは、NewEligible requestの`observed_term`はcurrent termと完全一致し、requested TTLは10秒固定でなければならない。`LeaseState::None`だけがgrant候補であり、Activeはdeterministic reject、Unknownはgenerationをconsumeしないpre-commit fail closedである。成功grantはWitnessだけがtermをchecked incrementし、独立CSPRNG UUIDv4 lease_idとmonotonic deadlineを生成する。deterministic rejectを含むauthority state・journal・watermarkは一つのatomic commitとする。

Duplicate grantは、保存済みgrantとcurrent Active authorityのterm・lease_id・holder・lease TTLが一致し、current durable authorityにmonotonic deadlineが存在するときだけremainingを再計算して再送できる。stored grantのabsolute deadlineとの比較は要求しない。remaining zeroまたはidentity不一致ではgrantを送らずfail closedとする。Duplicate、Retired/Stale、GenerationGap、pre-commit failureはいずれもauthorityを再実行せず、termやleaseを二重生成しない。これはfencingを提供せず、lease expiry processingも実装しない。

Stage 5のLEASE_RENEW authorityは、current Active leaseのterm・lease_id・holder本人・TTL 10秒・deadlineを確認し、`now < deadline`の場合だけ更新を許可する。更新はterm・lease identityを変更せず、`now.checked_add(10_000ms)`を新deadlineとする。期限切れActiveはrenewせず、None/UnknownをActiveへ変換しない。成功renewal、journal result、watermarkは一つのatomic commitとし、commit前失敗は状態を変更しない。

Duplicate `LEASE_RENEWED`はcurrent durable authorityのidentityとdeadlineを使ってremainingを再計算し、期限を再延長しない。後続renewalでdeadlineが更新されていても、stored resultのabsolute deadlineとの一致は要求しない。remaining zero、identity不一致、metadata欠落、clock failureはfail closedである。Witness renewal成功はNodeのlocal safetyやfencingを証明しない。Stage 5ではこのrenewal authorityを実装済みである。

Stage 5.9でLEASE_RELEASE authorityの安全境界を固定した。current Active authorityとterm・lease_id・holderが一致するreleaseは、期限確認なしにleaseを解放できる。成功commit後のauthorityはtermを維持し、lease metadataをすべてNoneとする。期限切れActiveをreleaseできることは、expiry処理やfencingを意味しない。Noneは過去のreleaseの証明ではなくreject、Unknownやmetadata不整合はpre-commit fail closedである。

成功したreleaseのDuplicateはjournalの歴史的結果を再送するだけで、現在Noneであることを要求せず、後続の別leaseをclearしない。Nodeはexact outstandingの歴史的term/lease_idとpayloadを検証してdurable completionできるが、response envelopeの新しいcurrent authorityを歴史的release結果と混同しない。これはrelease mutationのcommitだけを証明し、現在None、旧Activeの停止、service停止、VIP解放、host停止、fencingの証明ではない。response送信失敗でもcommitをrollbackしないため、Nodeのlocal demotionはWitness releaseを待たない。

### Stage 6.9 Witness lease expiry processing policy

expiryはWitness-local authority maintenanceであり、Ready、整合したActive metadata、same-boot monotonic deadline、clock read成功、`now >= deadline`をすべて満たす場合だけ既存atomic durable saveでActiveからNoneへ遷移する。`now < deadline`、None、Unknown、NotReady、metadata不整合、clock failureはno-opまたはfail closedとする。termは変えず、lease_id・holder・TTL・deadlineを消去し、journalとwatermarkは変更しない。

GET_TERMはread-onlyを維持し、expiry未処理のexpired Activeをremaining 0として報告できる。LEASE_REQUESTはimplicit expiryせず、expiry commit後のNoneに対してだけ新termのgrant候補となる。expiry・renew・releaseは同一authority snapshotを直列化し、renew後のstale expiry clearとexpiry後のstale renew resurrectionを防ぐ。expiryはrequest_id、mutation_generation、journal、responseを持たず、fencing、service/VIP停止、旧Active停止、実リソース唯一性を証明しない。OS boot_id変更時は既存どおりNotReadyで自動expiryしない。

Stage 6.9でpolicyを固定し、Stage 7でexpiry maintenance primitive、Stage 8でscheduler/runtime integrationを実装済みである。

Stage 6でLEASE_RELEASE authorityを実装済みとする。Stage 7でWitness lease expiry maintenance primitive、Stage 8でそのscheduler/runtime integrationも実装済みである。Node allocator、Node demotion integration、fencingは引き続き未実装である。

Stage 7.1では、4種類のdurable authority mutationをprocess-local Mutexの同一境界で直列化し、stale candidateのcommit、renew後の古いexpiryによるclear、expiry後の古いrenewによるresurrectionを禁止する。Mutex poisonは安全な回復根拠がないため`AuthorityLockPoisoned`としてfail closedにし、durable authority・journal・watermarkを変更しない。この境界はfencingではなく、別process・別hostの実リソース停止も証明しない。

Stage 8 schedulerはsleep/wait中にauthority Mutexを保持せず、wake後にcurrent durable state、same-boot monotonic now、deadlineをStage 7 primitiveで再検証する。early wakeはNotExpired、late wakeはcurrent deadlineに従う。scheduler停止や遅延はdeadlineを延長せず、Witness expiryはNode local expiry/demotionやfencingを代替しない。

Stage 2.0.1のrequest_id journalは、mutating authority副作用のdurable idempotencyを担う。same request_idでsemantic identityが一致するretryはcommitted resultを再利用し、mutationを再実行しない。一方、同じrequest_idでrequest kind、requester、fingerprintが異なる場合はConflictとしてfail closedにする。journal corruption、duplicate record、malformed recordはjournalだけを捨てず、Witness全体をNotReadyにする。

journalのbounded evictionは安全性の根拠ではない。journal missは「never committed」を意味せず、retirement proofなしに新規mutationへ進んではならない。capacity fullで安全にretireできるrecordがない場合は、新規mutating requestを拒否してavailabilityを低下させる。これはidempotency knowledgeを失って二重authority mutationするより安全側の選択である。request_idのUUID uniquenessは偶発的collisionを抑止するが、retentionやretirement proofの代替ではない。

authority state mutation、idempotency result、retirement metadataは1つのcandidate stateとして同一のdurable atomic saveでcommitする。persist成功後にresponse送信が失敗してもstateやjournalをrollbackせず、retry時にjournal resultを再構築する。sequence/session replay protectionはtransport/runtime境界であり、request_id journalを代替しない。Stage 2.0.1の時点ではauthority execution自体は未実装だったが、Stage 4ではLEASE_REQUESTに限りこの境界へ接続する。

Stage 2.0.2では、既存のterm、lease_id、observed_termだけではbounded journal eviction後の古いretryと新しいmutationを安全に区別できないため、mutating Witness requestにrequester nodeごとのdurableな`mutation_generation`を追加する。Witnessは`highest_committed_mutation_generation`をauthority state、journal、retirement metadataと同一のatomic saveで保持する。journal missは実行許可ではなく、active recordの完全一致はDuplicate、watermark以下はRetired/Stale、`watermark + 1`と一致する場合だけがNewEligible候補、それを超える場合はGenerationGapとしてfail closedとなる。retirement proofなしのevictionまたはcapacity超過、generation counterのrollback・喪失・再初期化はfail closedとする。

このwire仕様訂正に伴うProtocol v1 freezeの一時解除は、wire型・canonical CBOR・HMAC対象・fixed vectorおよびtestsの更新後に完了し、現在は訂正後のlayoutで再freeze済みである。fencingなしで旧Active停止や実リソース唯一性を保証できないという既存の限界は変わらない。

Stage 2.0.3では、Witness watermarkをcontiguous high-waterとして扱う。`watermark + 1`以外の新規generation、generation 0、u64 overflow、arbitrary jumpは拒否する。Nodeのcounterまたはoutstanding stateのrollback・喪失・破損、同じnode_idの再利用、Witnessのgeneration state rollbackは自動修復せずfail closedとする。validな古いWitness snapshotはboot_id不一致やatomic file破損とは異なり、単一の有効なstate fileだけでは一般に検出できない。

Retired/Staleは元requestのsuccessを証明しない。LEASE_REQUESTは現在のterm/lease/holderを再観測しても元grantと区別できなければpromotion authorityに利用せずRecoveryPending、LEASE_RENEWはdeadline延長とみなさずcurrent leaseを再観測またはdemotion、LEASE_RELEASEはcleanup proofとみなさずactive leaseなら旧requestを再実行せず明示的reconcileとする。local demotionはLEASE_RELEASEやWitness queueを待たない。

Stage 9ではNode側の`highest_started_mutation_generation`を「durably開始した最大generation」と定義し、NodeMutationPersistentState、explicit initialization、durable allocator、exact recovery、terminal completion primitiveとして実装した。新規logical mutationはgeneration、fresh request_id、完全なsemantic payload、outstandingを一つのatomic durable candidateとしてpersistしてから送信する。persist成功後はそのgenerationを再利用せず、restartやresponse lossでは同一logical identityをretryする。completionはAcceptedSuccess、DeterministicReject、RetiredStaleだけをclear可能とし、Conflict、GenerationGap、transport/timeout/NotReady等ではoutstandingを維持する。

Node mutation stateはWitness v2と別schema/versionであり、missing fileをbrand-newの証明とみなさない。通常runtimeはmissing/corrupt/unknown version/identity mismatchをfail closedとし、explicit initialization以外でgenerationをresetしない。同じnode_idの再利用、validな古いsnapshotへのrollback、initialization_id喪失を自動修復できない限界を明示し、管理者reconcileまたはidentity replacementを要求する。local service停止・VIP解放等のdemotion safetyは、Witness mutation queueの有無に依存しない。

Stage 9.9.2では、Stage 9.9.1で固定したWitness mutation outcome taxonomyをauthenticated `LEASE_REJECT.code`として実装した。`POLICY_REJECT`はdurably committed deterministic rejectとしてoutstandingをclearできるが、成功を意味しない。`RETIRED_STALE`はlocal queueだけをclearできるが、元のgrant/renew/release成功を証明せず、request kindごとのreconcileを要求する。`CONFLICT`と`GENERATION_GAP`はidentity/contiguous generationの安全性問題であり、clear・generation jump・request rewriteを行わずRecoveryPending/admin reconcileとする。`TEMPORARILY_UNAVAILABLE`、pre-commit failure、response loss、timeout、相関失敗はterminalとせず、同一logical mutationをretainする。reason文字列は診断情報であり、machine classificationには使用しない。code追加によるProtocol v1 wire訂正は再freeze済みだが、persistent v2・journal・watermarkの意味は変更していない。

### Stage 10 Node durable Witness mutation runtime

Node側のmutation runtimeは、durable beginまたは既存outstandingの再利用後にだけ送信する。responseは既存のcanonical decode、HMAC、semantic validation、Witness identity/session/replay、request_idおよびresponse-kind correlationを通過してから分類する。成功・`POLICY_REJECT`・`RETIRED_STALE`だけがStage 9 completion対象であり、completionのdurable saveが成功するまでlocal completionを報告しない。

`RETIRED_STALE`はqueue terminalだがWitness mutationの成功・失敗を証明しない。`CONFLICT`と`GENERATION_GAP`はoutstandingをclearせず、generationやrequest_idを修復・更新しない。`TEMPORARILY_UNAVAILABLE`、timeout、response loss、認証・相関失敗もoutstandingを保持する。Stage 10はreason文字列を分類に使用せず、NodeState、local lease expiry、service/VIP、promotion/demotion、fencingを変更しない。

MVPが保証するのは、認証されたterm/leaseの整合性、保守的なpromotion抑止、正常なNodeのlease喪失時demotion開始、cleanup未確認時の自動promotion抑止である。

MVPは、外部リソースの唯一性、旧Activeの停止、fencing、実ネットワーク上のVIP唯一性を保証しない。

## Stage 11 lease authority contract

Stage 11では、Nodeは各transport attemptの送信直前にlocal monotonic timestampを`attempt_start`として記録し、`attempt_start + lease_remaining_ms - 2秒`を保守的な`local_safe_deadline`としてruntime-onlyで保持する。受信時刻をoriginにしてresponse生成・送信遅延を無視してはならない。`remaining <= 2秒`、clock read failure、加算overflow、deadline到達済みはusable lease authorityを生成しない。wall clock、Node/Witnessの時計同期、Witnessの絶対時刻は使用しない。

`Candidate`はauthorityではない。conservative modeのpromotion guardは、Candidate、Recovery Ready、state-machine guard、Witness Ready、exact outstanding absence、認証済みかつcorrelatedなLeaseRequest success、term/lease_id/holder一致、local_safe_deadlineが現在より後であることをすべて要求する。priority、heartbeat、peer health、Witness TCP接続だけでは不十分である。`PromotionAuthorized`はruntime-only predicateであり、NodeState::Activeやresource ownershipを意味しない。

LEASE_RENEWEDは、request送信や応答受信だけではdeadlineを延長しない。認証、request_id/kind、term、lease_id、holder、semantic validation、Stage 10 durable completion、safe deadline構築の後にだけdeadlineを置換する。durable completion後に旧safe deadlineを再確認し、旧期限を跨いでいればrenewed authorityをinstallせずdemotionを不可逆に維持する。AcceptedSuccessはmutationのterminal classificationであり、応答が遅くsafe deadlineを過ぎていればleaseをusableとは扱わない。

safe deadlineに到達したActiveは、Witness release成功やpeer takeoverを待たずlocal demotionを開始する。service停止確認とVIP解放確認を先に行い、その後にLeaseReleaseをbest effortで実行する。demotion latchが立った後、late response、peer recovery、Witness recovery、heartbeat recoveryはdemotionをcancelしてActiveへ戻せない。Witness unreachable、NotReady、応答欠落はlocal demotionを禁止する理由にならない。

Stage 11 invariants:

- S11-I01: Candidateだけではresource actionを開始しない。
- S11-I02: conservative promotionはusableなlocal Witness leaseを必須とする。
- S11-I03: lease usabilityはvalidated remainingとlocal monotonic timeだけから導く。
- S11-I04: validated/durable renewal success前にdeadlineを楽観的に延長しない。
- S11-I05: safety boundary喪失はWitness到達性と独立してlocal demotionを開始する。
- S11-I06: RecoveryPendingとFailedはpromoteしない。
- S11-I07: outstanding mutation Nがある間はN+1をallocateしない。
- S11-I08: process restartは旧runtime lease authorityを復元しない。
- S11-I09: heartbeatとpriorityはcandidacy入力でありauthorityではない。
- S11-I10: local resource cleanupはWitness release successを待たない。
- S11-I11: AcceptedSuccessでも遅延によりleaseがusableでない場合がある。
- S11-I12: lease acquisitionからresource phasesを経ずにActiveへ遷移しない。
- S11-I13: remainingは保守的にboundedされ、local authorityをWitness expiry後へ延長しない。
- S11-I14: resource stepとActive遷移の各境界でauthorityを再検証する。
- S11-I15: renewal durable completion中に旧safe deadlineを跨いでもActive authorityを復活させない。
- S11-I16: authority lossで開始したdemotionはcurrent operation中に不可逆である。
- S11-I17: restartはlease通信だけでresource reconciliation完了とは扱わない。
- S11-I18: RecoveryPendingはWitnessなしでlocal resource cleanupを実行できる。
- S11-I19: unresolved LeaseReleaseはcleanupを阻止せず、future promotionとN+1を阻止する。

Peer disappearanceはCandidateを許可する入力に留まり、Witness leaseなしのpromotionは行わない。Witness unreachableまたはNotReadyの場合、既存Activeはlocal safe deadlineまでだけ継続し、その後demoteする。grant/renew response loss、transport/auth/correlation uncertainty、Conflict、GenerationGap、TemporarilyUnavailableはexact outstandingを保持しpromotionを禁止する。RetiredStaleは成功を推測せず、reconcile後までpromotionを禁止する。PolicyRejectはterminal unsuccessfulとしてclearできるがlease successではない。

renew responseがsafe deadline後に到着した場合、mutation completionとauthority usabilityは別に扱う。履歴上mutationを完了できてもresource ownershipの継続や新しいpromotionは許可しない。monotonic clock failureとNode restartも同じfail-closed結果とする。QuorumUnknownはzero-resourceならCandidateへ進めるが、resource-owningならlocal demotionを優先する。RecoveryPendingはGET_TERMまたはexact outstandingのreconcileだけを許可し、fresh LeaseRequestを回復の近道にしない。Failedは`reset_for_recovery()`後にだけreconcileし、MaintenanceとIsolatedはautomatic acquisitionを行わない。

availability modeではWitness leaseのsafe deadline、renewal、lease-loss demotion gateを適用しない。local_epochと明示force failoverを既存仕様どおりに使うが、resource stepごとのlocal checksは維持し、split-brain riskは残る。

### Stage 11.3 ResourceExecutor invariants (design only)

- S11.3-I01: 観測が必要なresourceではcommand returnだけでlocal stateを証明しない。
- S11.3-I02: ownership-affecting action後のtimeout/errorは、trusted observationが証明しない限りUnknownとする。
- S11.3-I03: ZeroResourceはVIP Absentかつservice Stoppedのtrusted local evidenceを要求する。
- S11.3-I04: ResourceOwning/Unknownはcaller assertionでZeroResourceにならない。
- S11.3-I05: health failureはresource absenceを証明しない。
- S11.3-I06: GARP failureはVIP absenceを証明しない。
- S11.3-I07: Activeはpromotion observations全てとfresh Stage 11.2 completionを要求する。
- S11.3-I08: cleanupはusable Witness authorityを要求しない。
- S11.3-I09: clean Standbyはlocal resourcesのconfirmed absenceを要求する。
- S11.3-I10: LeaseRelease successはlocal resource absenceを証明しない。
- S11.3-I11: restartでruntime permissionとresource resultを破棄する。
- S11.3-I12: persisted OperationPhaseはresource truthではない。
- S11.3-I13: post-action uncertaintyはUnknown、cleanup、reconcileへ進む。
- S11.3-I14: availability modeもlocal observation truthを弱めない。
- S11.3-I15: confirmed resource factsはtrusted executor/reconciliation provenanceだけが生成する。
- S11.3-I16: ownership-affecting action後のcompletion failureでZeroResourceを維持・復元しない。
- S11.3-I17: RecoveryBlockedは将来のtrusted local reconciliationだけで解除可能とする。
- S11.3-I18: action/diagnostic outcomeとtrusted resource observationは独立し、timeout/errorだけではresource truthをUnknownに上書きしない。
- S11.3-I19: Resource observation Unknownとcontroller ownership Unknownは別層であり、Confirmed Running/Stopped/Present/AbsentをUnknownへ書き換えない。
- S11.3-I20: Stage 11.2 authority permissionはpromotion・ownership acquisition・continued ownershipに限り、local cleanup・rollback・reconciliationには要求しない。
- S11.3-I21: command stopのexit 0とhealth非正常はConfirmedStoppedを証明せず、trusted停止観測がなければConfirmServiceStoppedで停止する。
- S11.3-I22: cleanup confirmation failureは既存state-machine契約に従いFailedとし、RecoveryPendingは後続の明示的recovery/restartで再観測する。

Stage 11.3はresource backendを実装せず、Protocol v1、Node Persistent v1、Witness Persistent v2、Recovery Transaction v1.2、journal/watermark、mutation_generation、Stage 10 taxonomy、Stage 11.1 timing、Stage 11.2 privacy/RecoveryBlocked、dependenciesを変更しない。

### Stage 13.3 authority-view evidence and no-fencing contract

This section supersedes the earlier Stage 13.3 corroboration wording.

#### What the evidence proves

- Local axis: **fresh** inability to communicate with the peer
  (`CommunicationLost` within a monotonic age bound).
- Authority axis: fresh authenticated `TermStatus` whose holder
  classification is `AuthorityViewCompatible`.

Together they prove only that policy may permit entering the mandatory
fresh lease-acquisition phase. They do **not** prove:

- the peer is dead
- the peer stopped serving
- resources were released
- fencing completed

#### Holder facts (Witness authoritative)

- `holder = None` → Witness records no lease holder for this term.
  Not proof of resource shutdown.
- `holder = Self` with `remaining > 0` → quorum fact only; not executable
  lease authority for this attempt.
- any `Some(holder)` with `remaining = 0` → expired-but-unprocessed;
  **fail closed** (GET_TERM does not perform expiry).
- `holder = Foreign` (any remaining) → **fail closed**.

Client code must not invent expiry that Witness has not committed.

#### No-fencing contract

Mikagami Stage 13.3 does not fence the old peer. `safe_deadline`
demotion is local and best-effort. Lease expiry is not resource fencing.
Stage 13.3 controls only whether lease acquisition may be attempted.
No Stage 13.3 evidence permits direct resource activation.

Duplicate serving remains a documented no-fencing risk if an old Active
fails to self-demote. A future explicit manual promotion path may accept
this under stated operator assumptions. Automatic failover must not be
enabled on this basis alone.

#### Naming

Authorization-relevant fusion success is `FailoverEvidenceReady`, not
`CorroboratedLoss`. Witness authority-view evidence is
`WitnessAuthorityViewEvidence`, not "reachable peer-loss proof".

Authorized remains ephemeral and unpersisted
(`Authorized != LeaseAuthority`).

## v1.0 追補（2026-10-11 Owner承認。正本は`MIKAGAMI_STAGE_15_V1_CONTRACT_AMENDMENT.md`）

上の「No-fencing contract」と「Automatic failover must not be enabled on this basis alone」は、Stage 13時点の記述である。v1.0では次が追加・置換される（Stage 14のfencing連鎖G→H→I→K→ARMは変更されない）。

- **自動切替は昇格要求の生成だけ**を自動化する。要求は手動SIGUSR1と同じ単一の試行経路に入り、全gateを毎回再評価する。peer喪失の経路は`fencing.backend = command`で`CONFIRMED`に到達した場合に限り、さらにこのプロセスがpeerを`Active`と連続2回以上観測した後の喪失に限る（再起動直後の推測では動かない）。`FAILED`（peerが隔離されていない）後は再fenceしない。
- **Bootstrap Admission（BA）**: 両ノードがStandbyで資源ゼロ、peerが健全な冷起動に限る入場クラス。順序は ①Witness `GET_TERM`でterm Tを基準に取る → ②基準を取った**後**にnonce付きprobeをpeerへ送り、peerは同一`tick_at`内で安全状態を再観測して`ACK`/`BLOCK`/`UNKNOWN`を返す → ③`LeaseRequest(observed_term = T)`（Witnessのcompare-and-setで高々1者） → ④grantが`T+1`でなければabort → ⑤BA用の平易なARM→authority復元→promote。**安全判定に経過時間・RTT・heartbeatの鮮度・定数間の関係を使わない**（`node.preferred`とdwellは「試みるか」の絞り込みと要求の時間差にだけ使う）。BAはConservativeモードでのみ成立する（`cluster.mode`は存在せず常にConservative）。Mikagamiの外側の主体がStandbyの資源を起動することは検出できず、運用で禁止する（`deployment.md`）。
- **Startup Obligation Reconciliation（SOR）**: 解放義務Oを持って再起動したノードは、trusted ZeroResourceを確認した後に限り、(i)exact release、(ii)Witnessの`current_term > term_o`、(iii)`current_term == term_o`でholderなし、のいずれかでOを解消してStandbyに戻る。`current_term < term_o`（巻き戻し）、同termで他者がholder、Mがある場合は解消しない。SOR自体は昇格権限を与えない。
- **Witness**: `mikagami witness run`が既存のauthority実装を無変更で使うサーバーになる。ホスト再起動後の再武装は1回の原子的commitで行い、termとholderは変えない。Witnessの状態が巻き戻されたことは検出できない（範囲外）。
- **commandサービス**: `status`の厳格な文法、`start`後は自分の`stop`が成功するまで`stopped`を信じない。外部プロセスがプロセスグループ外に切り離した孫プロセスはMikagamiの制御外。同じグループに残る子は、`KILL`の成否とグループが空であることの確認（リーダー回収後はシグナル0のみ。回収済みのIDには破壊的シグナルを送らない）まで責任を保持し、確認できない間は`stopped`を信じず、後続の起動もしない。`stop`の清掃が不確定な場合、その`stop`は成功に数えない。

## v0.7 追補（正本は`MIKAGAMI_V07_CONTRACT_AMENDMENT.md`）

上の各節と「v1.0 追補」に、次を加える。条文の全文、出典、裁定は正本にある。

- **稼働中の解放不能のsettle（Amendment C の C-a）**：post-cleanupのexactなReleaseが、認証済みで対応するPolicyRejectを受け、E-1〜E-8をすべて満たす場合に限り、MとOを1回の原子的な保存で消してStandbyに戻る。Releaseの成功ではなく、昇格の根拠にならない。条件が一つでも欠ければ従来どおりRecoveryBlocked。
- **起動時のC-l**：起動時の照合で、exactなReleaseの再送がRetiredStale（Witnessのjournalの記録が消えた後）の場合に限り、同じsessionで新しくGET_TERMのviewを取り、既存の`decide`がClearSupersededを返し、viewが自分を期限の残るholderと示さない時だけ、MとOを消す（superseded、not released）。稼働中のRetiredStaleはRecoveryBlockedのまま。
- **例外のclearの共通の条件（C-m'）**：起動時のA-4d、C-a、C-lのどれも、保存の直前にtrusted ZeroResourceを確かめ直し、同じstoreのguardの中でfencingのincidentが無いことを確かめる。
- **再送の間隔と有界の再試行（C-c / C-d、LIM-CD-1）**：同じsessionでtimeoutしたretainedなRenewの再送は、上限60秒の指数の間隔で間引く。`UncorrelatedResponsesExhausted`は結果の不明として扱い、同じexactな要求を連続3回まで再送し、その後は既存の経路（Activeなら降格、post-cleanupならlatch）。稼働中のretainedなRequestは自動で再送しない。
- **Witnessの永続性の前提（C-W1）**：上の解消と既存のexact release、A-4d、SORの`decide`は、Witnessの状態が巻き戻されないことに依る。Witnessのstate directoryをbackupやsnapshotから戻してはならない（A-c1 / A-c2）。`on_reboot = "refuse"`は補助策で、巻き戻しの検出の手段ではない（A-c3）。
- **health**：Activeの間のhealthの失敗は警告のログだけで、降格、再起動、切替をしない（v1.0 D-5。`state-machine.md`）。
- **GCEの経路の引き継ぎ（G-2 route handoff）**：内部の昇格の完了（`Succeeded`）は切替の成功ではない。daemonが出す最大の値は`ROUTE_CONFIRMED`で、serviceへの到達はこのnodeでは確かめない。GCEへの自動の書込みはtermごとに`route-assign` 1回と、条件R-1〜R-9を満たす時の同じ要求の`route-reissue` 1回だけ。routeの失敗を理由に降格や切替をしない。詳細は[`gce-fencing.md`](gce-fencing.md)。
- **二重のwriterの範囲**：v0.7が保証するのは、Witnessのlease、guestのVIP、GCEのaliasの経路、管理するserviceのactiveの所有権である。共有のstorage、外部のdatabase、applicationの内部のdataの一貫性は保証しない。
