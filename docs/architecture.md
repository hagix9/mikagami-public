# Architecture

> 開発者向けの設計・検証の記録です。開発の工程の識別子（段階や判断の番号）と、公開候補に含まれない内部の資料への参照を含みます。利用の手順は [`README.md`](../README.md) と [`configuration.md`](configuration.md) を参照してください。

## Scope

Mikagamiは2ノードのActive/Standby構成を管理する。MVPの正式対象はsystemdを利用できるLinuxであり、1つのサービスと1つのIPv4 VIPを扱う。

## Components

```text
Node A                         Node B
┌──────────────────┐           ┌──────────────────┐
│ Mikagami Core    │◄─────────►│ Mikagami Core    │
│ NetworkBackend   │ heartbeat │ NetworkBackend   │
│ ServiceBackend   │           │ ServiceBackend   │
│ FencingBackend   │           │ FencingBackend   │
└────────┬─────────┘           └────────┬─────────┘
         └──────────────┬───────────────┘
                        ▼
                    Witness
```

conservativeモードの自動HAではWitnessが必要であり、可用性上の依存点になる（Witness構成）。Witnessを使わない2ノード構成（`cluster.topology = "two-node"`）は別のruntimeとして追加した（[`TWO_NODE_ARCHITECTURE.md`](../TWO_NODE_ARCHITECTURE.md)）。Witnessはterm authorityとlease authorityを担うが、fencingは行わない。

Coreは状態機械、promotion guard、lease判定、操作順序を管理する。Linux固有のVIP操作やsystemd操作はbackendに分離する。

Recovery Transaction Contract v1.1では、canonical pathごとにprocess-global transaction lockを共有し、recovery inspection、immutable canonical snapshot取得、canonical persistenceを同じ直列化domainへ置く。PREPAREはhard-linkによるatomic no-overwrite install、temporary fileはtransaction-unique nameを使用する。Recovery Metadata v1のオンディスク形式、Node Persistent v1、Witness Persistent v2は変更しない。通常reader／writer／GET_TERM／schedulerは同じuncertainty gateを通り、network I/OはRecovery lock外で行う。v1.2では、親symlinkと`..`をfilesystem semanticsどおりに解決するResolvedStorePath、およびsnapshot provenance必須のcandidate APIを実装し、決定的な直接テストで検証済みである。Stage 11へ進む前に残る未検証境界は引き続き明示する。

authorityが不確実になったActiveは`QuorumUnknown`へ遷移後もlocal demotionを開始できる。これはauthority再取得やWitness応答を必要としない安全側のrelinquish pathであり、promotion pathではない。demotionの既存順序とOperationPhaseは維持する。

永続化はcanonical Node/Witness stateと外部のRecovery Metadata v1を分離する。durable PREPAREを先に確立し、canonical rename／hard-linkとparent directory fsyncが確認されるまでauthorityやNode mutationを成功扱いしない。commit後のmarker cleanupが不確定でもmarkerが残れば保守的にrecoveryへ入り、可視file、parse成功、fingerprint一致だけでReadyへ戻らない。Node Persistent v1、Witness Persistent v2、journal、watermark、Protocol v1は変更しない。

Protocol v1のTCP listener、1接続単位のHELLO handshake primitive、`PeerConnectionManager` primitiveを提供する。permanent accept loop、daemon connection manager統合、reconnectは未実装である。

`PeerConnectionManager`はcanonical connection directionとprocess-localなpeer replay memoryを管理し、最大1本のcanonical established connectionを保持する。daemonのaccept loop、reconnect scheduler、heartbeat runtimeは別工程である。

manager所有connection上のHEARTBEAT/HEARTBEAT_ACK一往復primitiveは実装済みである。認証・検証・peer sequence high-water commitまで完了したHEARTBEAT/HEARTBEAT_ACKだけがlast-success trackerを更新するintegration primitiveも実装済みである。heartbeat scheduler、liveness transition、reconnect、daemon統合は未実装である。

established Node peer connectionの受信messageを、認証済み・共通peer検証済み・replay-freshな`PendingPeerMessage`として1件ずつ分類するdispatcher primitiveを提供する。dispatch時はhigh-waterをcommitせず、handlerの受理後に明示的なcommitを行う。dispatcherはsingle-threaded、one-message-at-a-timeのruntime ownershipを前提とし、schedulerは未実装である。

dispatcher-backed heartbeat runtime primitiveは、Pending HEARTBEATをcommit・liveness更新・ACK送信の順で処理し、送信側ではHEARTBEAT送信後に`AwaitingAck`としてPending ACKをdispatcherから受理する。既存のblocking heartbeat primitiveは維持し、周期scheduler、timeout判定、reconnect、daemon統合は未実装である。

single-threaded established peer runtime ownership primitiveも実装済みである。`process_next_peer_message()`は1回につき最大1件を`dispatch_next()`から受信し、HEARTBEAT/HEARTBEAT_ACK、STATE_ANNOUNCE/STATE_ANNOUNCE_ACK、PROMOTION_INTENT/PROMOTION_ACK/PROMOTION_BLOCK/PROMOTION_UNKNOWN/PROMOTION_COMMITTED、DEMOTION_INTENT/DEMOTION_ACK/DEMOTION_COMMITTEDを内部handlerへroutingする。将来のdaemon runtimeではこのdispatcher-backed pathだけをcanonical receive pathとし、legacy blocking heartbeat APIと同じconnectionで同時利用しない。

Promotion peer coordination runtimeの第1段階も実装済みである。`PROMOTION_INTENT`はoperation_idを保持するoutstandingとともに送受信し、受信側はintentを観測値としてcommitする。`PROMOTION_ACK`、`PROMOTION_BLOCK`、`PROMOTION_UNKNOWN`は明示的な送信primitiveとoperation_id correlation付き受信handlerで処理する。`PROMOTION_COMMITTED`は専用ACKなしのpeer-reported observation/eventとしてhigh-water commit後にcallerへ返す。これらはいずれもauthorityを生成せず、NodeState、lease、livenessまたは実際のpromotionを変更しない。

Demotion peer coordination runtimeも実装済みである。`DEMOTION_INTENT`は明示的な`DEMOTION_ACK`交換を前提にoperation_idでcorrelateし、ACK受信時に対応するcommunication-level DemotionOutstandingを完了する。`DEMOTION_INTENT`と`DEMOTION_COMMITTED`はhigh-water commit後にpeer-reported observationとして返し、後者は別の専用ACKやoutstanding completionを持たない。これらはdemotion completion、service/VIP操作、lease解放、fencingを証明せず、実際のresource demotionは未実装である。

Witness Runtime Stage 1はNode peer runtimeと分離されたtransport/runtime境界として、9種類のWitness messageの分類、authenticated receive、request_id correlation、Pendingからhigh-water commitまでを提供する。Stage 1は観測と既決定responseの送受信のみを行い、term/lease authority、永続化、boot_id復旧は未実装である。

Witness Runtime Stage 2では、persistent authority stateを`witness_state` moduleで管理する。状態ファイルはProtocol v1 wire dataとは別形式で、validation、boot_id比較、同一bootでのmonotonic deadline復元、fail-closed readinessを担当する。保存はtemporary fileへのwrite/fsync、atomic rename、parent directory fsyncの順序で行う。Stage 2もStage 1のmessage handlerやauthority decisionには接続しない。

Witness Runtime Stage 3では、認証・semantic acceptance・replay commit済みの`GET_TERM` observationだけを、`witness_authority`のread-only layerへ渡す。`WitnessReadiness::Ready`かつlease stateが`None`または`Active`の場合だけ、durable stateから`TERM_STATUS`をprepareする。transport、persistent state、authority projectionの3層は分離し、term/lease mutationは行わない。

Stage 2.0.2では、bounded request journalのeviction後の安全なretirement proofに必要な`mutation_generation`をmutating Witness requestへ追加する仕様訂正を行った。requester nodeごとのdurable watermarkをauthority state、journal、retirement metadataと同一のatomic saveで管理する。

Stage 2.0.3では、contiguous requester watermarkをWitnessが管理し、new requestは`watermark + 1`だけを候補とする。generation allocatorはNode側に置き、counterと完全なoutstanding mutationをatomicに保存してから送信する。requesterごとにone-outstandingとし、restart・send uncertainty・response lossでは同一identityをretryする。deterministic terminal decisionはgenerationをconsumeし、commit前のtransient failureはconsumeしない。Retired/Staleはsuccess proofではなく、request kindごとの再観測またはRecoveryPendingを選択する。local demotionはWitness mutation queueに依存しない。Protocol v1 wire contractはこのcorrection後のlayoutで再freeze済みであり、Stage 2.1はこのwire contract上で実装する。

Witness Persistence Stage 2.1では、mutating Witness requestのdurable idempotency journalをpersistent authority stateへ実装済みである。journalは64件のbounded active/recent recordとし、authority state・journal・generation watermark・retirement metadataは1つのcandidate stateとして同一のatomic durable saveでcommitする。journal missは未commitの証明ではなく、安全にretireできるrecordがない場合は新しいmutating requestをfail closedで拒否する。legacy Stage 2/3 stateは、Stage 4 authorityが未実装だった時点のhistorical invariantに基づき、明示的migrationでformat v2へ移行しempty journalとする。

versionless legacy Witness stateは通常load、GET_TERM、authority、scheduler経路では自動移行せず、`MigrationRequired`としてNotReadyにする。configured clusterとcurrent boot_idを確認できる場合に限り、管理者の明示的migration APIがF-01.1 transactionを通してv2へ移行する。

Stage 3.9では、Stage 4 `LEASE_REQUEST` authorityのpolicy境界を固定した。NewEligibleのみをauthority評価し、observed termはcurrent termと完全一致、TTLは10秒固定、`LeaseState::Active`はdeterministic reject、`Unknown`はpre-commit fail closedとする。成功grantではWitnessがcheckedにtermを1つ進め、独立したCSPRNG UUIDv4 lease_idと同一bootのmonotonic deadlineを生成する。authority state・journal・watermarkはcandidateとして一度だけdurably commitする。Duplicate grantはcurrent authorityのterm・lease・holder・TTLとdurable deadlineの存在を検証し、stored grantのabsolute deadlineとは比較せずremainingを再構築する。Stage 4のLEASE_REQUEST authority runtimeは実装済みであり、LEASE_RENEW/RELEASE authorityとexpiry処理は未実装である。

Stage 4.9で固定したLEASE_RENEW authority policyをStage 5として実装済みである。current Active leaseのterm・lease・holder・TTL・deadlineを検証し、`now < deadline`だけをrenew候補とする。成功時はterm・lease identityを変更せず、Witnessのmonotonic `now + 10s`へdeadlineを更新し、authority state・journal・watermarkを一つのatomic candidateとして保存する。Duplicate renewalはcurrent deadlineからremainingを再構築するが、deadlineを再延長しない。LEASE_RELEASE authority、expiry処理、Node allocatorは未実装である。

Stage 5.9で固定したLEASE_RELEASE authority policyをStage 6として実装済みである。current Active authorityとterm・lease_id・holderが一致するreleaseは、期限切れでもtermを変えずにlease metadataをNoneへするcandidateとして扱い、authority state・journal・watermarkを同じatomic saveでcommitする。Duplicate成功は保存済み結果を再生するだけで、後続leaseを変更しない。Noneはdeterministic reject、Unknown等はpre-commit fail closedである。Stage 7でWitness lease expiry maintenance primitive、Stage 8でそのscheduler/runtime integrationを実装済みである。Stage 9.0でNode mutation persistence contractを固定したが、Node allocator実装は未実装である。

### Stage 6.9 Witness lease expiry processing policy

expiryはWitness-local authority maintenanceとして独立したdurable mutationである。Protocol message、request_id、mutation_generation、journal record、watermarkを追加・変更せず、same-boot monotonic deadlineを再観測して`now >= deadline`のときだけActiveをNoneへ遷移させる。termは維持し、lease_id・holder・TTL・deadlineを消去する。既存のatomic saveに失敗した場合は旧Activeを維持し、memory上だけのclearや新lease grantを許可しない。

GET_TERMはread-onlyのままであり、未処理のexpired Activeをremaining 0として返せる。LEASE_REQUESTはimplicit expiryを行わず、expiry commit後のNoneに対してだけ次termのgrantを行う。expiry、renew、releaseはstale snapshotのlost updateを防ぐ同一のauthority serialization boundaryを必要とする。Stage 8 schedulerはこのboundaryをsleep中に保持せず、wake後にStage 7 primitiveへ再委譲する。Protocol v1とpersistent v2はFROZENのままである。

### Stage 9.0 Node mutation persistence contract

Nodeのmutating Witness request用stateはWitness persistent v2と分離した専用format v1とする。`initialization_id`、`highest_started_mutation_generation`、最大1件の完全な`outstanding_mutation`を保持し、generationとoutstandingをpersist-before-sendで一つのatomic candidateとしてcommitする。generation counterはhighest durably started generationであり、terminal completion後も保持する。missing stateは自動bootstrapせず、explicit initializationまたはRecoveryPending/admin reconcileを要求する。

restart、send uncertainty、response lossではrequest_id、generation、kind、semantic payloadを完全に維持してretryする。session_id、sequence、HMAC、wire bytesは保存しない。completionは明示的terminal dispositionとidentity一致を要求し、保存成功前にoutstandingをclearしない。local demotionはこのone-outstanding Witness mutation制約に依存しない。

Stage 9ではNodeMutationPersistentState、NodeMutationStore、explicit initialization、durable allocator、exact recovery、terminal completion primitiveを実装済みである。Stage 10でWitness transport/response integrationのone-shot runtimeを実装した。explicit init CLI、retry scheduler、RetiredStale higher-level reconcile、Node demotion、fencingは未実装である。state rollback、state loss、同じnode_idの再利用は自動修復しない。

### Stage 10 Node durable Witness mutation runtime

`NodeWitnessMutationRuntime`は、`NodeMutationStore`のdurable beginまたは既存outstandingのload、persist-before-send、durable payloadからのProtocol request再構築、既存`WitnessConnection`でのone-shot送受信、認証・相関済みresponseの分類、terminal outcomeのdurable completionを担当する。新規mutationとretryを分離し、retryではrequest_id、mutation_generation、kind、semantic payloadを変更しない。TCP送受信はNode mutation persistence lockの外で行い、transport envelopeは現在渡されているProcessSessionのsession_idとsequence allocatorに従って再構築される。logical mutation retry自体はProcessSessionの再生成や新session_idを意味しない。

成功と`POLICY_REJECT`はdurable completion後にだけcompleted resultとして返す。LEASE_RELEASEの歴史的Duplicate成功は、exact outstandingの歴史的payloadを検証したうえで、current Witness envelopeが後続authorityを表していてもAcceptedSuccessとしてcompletionする。これは現在のlease不在やresource cleanupを意味しない。`RETIRED_STALE`はqueueをdurably clearするがreconcile-required result、`CONFLICT`/`GENERATION_GAP`はoutstandingを保持、`TEMPORARILY_UNAVAILABLE`・transport error・response lossもretainする。Stage 10はretry loop、reconnect、GET_TERM reconcile、NodeState、lease local expiry、service/VIP、promotion/demotion、fencingを実行しない。

Stage 10の直接テストは、3種類のfresh mutation success、durable outstandingのexact retry、response loss、相関・semantic mismatch、typed reject分類、completion ambiguity、F-01 recovery gatingを実TCP runtime境界で検証する。認証・canonical CBOR・journal・Witness authority policy・filesystem recoveryは主に下位層テストであり、Stage 10の完全なend-to-end統合テストを意味しない。

### Stage 9.9.2 Typed Witness mutation outcome protocol correction

Stage 9.9.2で、Witness mutationのNode actionを5つのtyped outcome codeとして`LEASE_REJECT`へ実装した。成功responseは変更せず、reason文字列はmachine classificationに使用しない。`POLICY_REJECT`はclear、`RETIRED_STALE`はqueueのみclearしてreconcile、`CONFLICT`/`GENERATION_GAP`はretainしてRecoveryPending、`TEMPORARILY_UNAVAILABLE`やno responseはretainしてexact retryとする。Protocol v1は一時unfreeze後に再freezeされ、pre-correction wire互換は提供しない。Persistent v2、journal、watermark、Node persistent v1は変更していない。

### Stage 8 Witness expiry scheduler/runtime integration

`WitnessExpiryScheduler`はdeadline観測、cancel可能な待機、wake後の`expire_lease_if_needed()`呼び出しだけを担当する。schedulerはauthority candidateを構築せず、timer wakeをexpiry proofとして扱わない。Noneはidle、NotReady/Unknown/clock failure等は固定retry intervalで再観測し、Mutex poisonはfail closedで返す。scheduler stateはprocess-local transientであり、persistent stateへ保存しない。

Stage 7.1では、LEASE_REQUEST、LEASE_RENEW、LEASE_RELEASE、expiryのload・validation/classification・candidate construction・durable commitを同一のprocess-local authority mutation Mutexで直列化する。response送信、socket I/O、GET_TERM、scheduler待機はcritical section外である。Mutexがpoisonした場合は`AuthorityLockPoisoned`でfail closedとし、poison recoveryやcandidate再利用は行わない。これはprocess-local serializationであり、fencingや複数process間の排他を提供しない。

elapsed `Duration`を分類するpure liveness classifierは実装済みである。runtime clock integration、scheduler、liveness transitionは未実装である。

monotonicなlast-success observation trackerも実装済みである。現在時刻は呼び出し側から`Instant`で渡し、起動直後は`NotObservedYet`とする。周期実行、duplex scheduling、runtime起動への統合は未実装である。

## Backends

MVPで使用するbackendは以下のとおり。

- NetworkBackend：Linux VIP backend。VIPのadd/delete/確認はnetlink、GARPは外部`arping`
- ServiceBackend：systemdまたはcommand
- FencingBackend：`None`

将来はNetworkBackendやFencingBackendをAWS等のplatform固有実装へ差し替えられる境界を維持する。ただしMVPでは汎用plugin frameworkを作らない。

## Authority and state

- Witnessあり：termを進められるのはWitnessだけ
- Witnessなしavailability：termではなく各Nodeの`local_epoch`として扱う
- priority：Active候補の選択だけに使用し、promotionの安全性判定には使用しない
- NodeState：ノードの役割・安全状態
- OperationPhase：promotion/demotion内部の進行状態

## Guarantees

MVPは安全側の状態遷移とcleanup確認を提供するが、fencingなしで旧Activeの停止や実リソースの唯一性を保証しない。詳細は[safety-model.md](safety-model.md)を参照。

## Stage 11 Lease Authority Integration Design

Stage 11は、既存のNode state machine、Node Persistent v1のdurable Witness mutation、Witness Persistent v2のauthorityを接続する設計段階である。Protocol v1、Node Persistent v1、Witness Persistent v2、Recovery Metadata v1、journal、watermark、mutation_generationは変更しない。VIP、service、GARP、fencing、automatic retry scheduler、GET_TERM reconcileのruntime実装は後段である。

Node側にはruntime-onlyの`NodeLeaseAuthority`を置く。値は`term`、`lease_id`、`holder_node_id`、`local_safe_deadline`、必要に応じて`last_validated_at`である。`local_safe_deadline`は同一processのmonotonic clock domainだけで有効で、Node Persistent v1へ保存しない。再起動後に旧deadlineを復元してleaseをusableとは扱わない。

`PromotionAuthorized`はNodeStateでも永続OperationPhaseでもなく、lease authority predicateの結果である。意味は「次のpromotion resource stepへ進む現在のlease authorityがある」に限る。VIP所有、service稼働、health成功、GARP成功、fencing、NodeState::Activeを意味しない。既存`PromotionPhase::AcquireLease`の完了後にこのpredicateを満たすことを、後続実装との境界とする。

Witnessの`lease_remaining_ms`を受信する論理mutationの最初のtransport attempt直前に、Nodeのmonotonic clockをtiming originとして一度読む。`local_safe_deadline = origin + (remaining - 2_000ms)`とし、request送信前からresponse生成・送信・受信までの経過をremainingから保守的に差し引く。同一`request_id`、`mutation_generation`、kind/payloadのretryではoriginを後続attempt時刻へ更新しない。remainingがmargin以下、clock failure、加算overflow、処理時点で期限到達済みの場合はusable authorityを作らない。2秒はこの経過時間の代替ではなく追加の保守窓である。

conservative modeのpromotion順序は、`guard → LeaseRequest/既存lease検証 → PromotionAuthorized → VIP acquire → service start → health → GARP → Active`とする。Candidateはpriority、peer liveness、peer health、peer停止観測だけではpromotionできない。Stage 11ではauthority gateまでを定義し、lease取得直後にNodeState::Activeへ遷移しない。

Renewalはgrant受信時刻から`renew_after_ms`を目安にmonotonicで一度だけスケジュールする。request送信、TCP response受信、Witness接続中という事実ではdeadlineを延長しない。認証、request correlation、term、lease_id、holder、semantic validation、Stage 10 durable completion、新しいsafe deadlineの構築が完了した後だけdeadlineを置換する。durable completion後に旧safe deadlineを再確認し、旧期限を跨いでいたらrenewed authorityをinstallせずdemotionを不可逆に維持する。outstanding renewal中はN+1を開始しない。

local safe deadlineに到達したActiveは、Witnessへのrelease成功やpeer takeoverを待たず、既存の`StopService → ConfirmServiceStopped → ReleaseVIP → ConfirmVIPReleased → ReleaseLease → CommitStandby`を開始する。authority lossがこのoperationを開始した後、late grant/renew、peer recovery、Witness recovery、heartbeat recoveryは現在のdemotionをcancelまたはActiveへ戻せない。LeaseReleaseはresource cleanup後にbest effortで行い、release通信がlocal cleanupを阻止してはならない。

| NodeState | authority条件 | Witness action | local resource action | 次のstate/phase | failure behavior |
|---|---|---|---|---|---|
| Standby | local lease不要 | guardとRecoveryがReadyならLeaseRequest可 | なし | Candidate、次にauthority gate | reject/uncertainはpromotion禁止 |
| Candidate | candidacyのみ、authorityなし | LeaseRequest可 | なし | AcquireLease/PromotionAuthorized | leaseなしならresource actionなし |
| Active | conservativeではusable lease必須 | exact current leaseのrenewのみ | safe deadline前だけ継続 | lease lossでdemotion | deadline/clock failureはlocal demotion |
| Degraded | resourceが残る場合もusable lease必須 | current leaseのrenewのみ | authorityがなければdemote | Active回復またはdemotion | 新規promotion不可 |
| Isolated | promotion authorityなし | automatic acquisitionなし | resource acquireなし | Standbyまたは明示recovery | fail closed |
| QuorumUnknown | authorityを意味しない | zero-resourceならCandidate経由で独立検証。resource-owningならreconcile/demotionのみ | resource-owningならlocal cleanup可 | zero-resourceはCandidate、resource-owningはdemotion | Candidate bypass禁止 |
| RecoveryPending | authority unusable/unknown | exact outstanding/GET_TERMのreconcileのみ | resource acquireなし。残存resourceはWitnessなしでcleanup | confirmed zero-resource後のみStandby | fresh LeaseRequestで回避しない |
| Maintenance | admin-controlled non-serving | automatic acquisitionなし | なし | admin exitまたはRecoveryPending | automatic promotion禁止 |
| Failed | recovery required | acquisitionなし | resource actionなし | `reset_for_recovery()`後のみ | fail closed |

availability modeは別のunsafe pathであり、local_epochと明示force failoverを既存仕様どおりに扱う。Witness authorityを要求する新しいsplit-brain保証は追加しない。priorityとheartbeatは候補選択の入力でありauthorityではない。

Process restartは新しいProcessSession/session_idを作る。TCP reconnectは同一ProcessSessionの既存契約に従う。論理retryは同じrequest_id、mutation_generation、mutation kind、semantic payloadを使う。LeaseRequest/Renew/Releaseのoutstandingは同一mutationとしてretryできるが、未解決のままN+1をallocateしない。restart後のruntime lease authorityは消去し、reconcileまたはvalidated grantを要求する。

### Timing origin, recovery, and implementation gaps

fresh responseとduplicate responseは同じ計算規則を使う。Witnessのfresh grantはauthority candidateのdurable commit後にresponseを作り、duplicate grant/renewはcurrent durable deadlineからremainingを再計算する。Nodeは保存済みhistorical remainingを再利用しない。論理mutationのretry/reconnectでは`request_id`、`mutation_generation`、kind/payloadに対応する同一のtiming originを保持し、後続attemptの送信時刻で安全期限を延長しない。response loss、reconnect、remaining不足、trusted timingなしではusable authorityを作らない。

Renewal completionが旧safe deadlineを跨いだ場合、mutationのdurable completionとresource authorityを分離する。renew resultを履歴上処理できても、renewed authorityをinstallせずdemotion latchを解除しない。resource operationの各step直前、health acceptance、GARP、CommitActive、Degraded→Activeの全入口でusable authorityとdemotion latchを再検証する。resourceを一部取得済みならpromotionを続けず、取得済み範囲のcleanupを行う。

再起動またはRecoveryPendingからのRecoveryReadyは、validated grant、GET_TERM success、outstanding retry successのいずれか一つでは成立しない。VIP不在かつservice停止、Recovery uncertaintyなし、persisted Node state valid、Witness readiness/current authority、peer観測、outstandingの状態を確認し、必要なlocal cleanupを完了して初めてStandbyへ戻す。VIPまたはserviceが残る場合はRecoveryPendingのcleanup operationで停止・確認し、Witness接続を待たない。不明な観測はFailedまたはRecoveryPendingに留める。

Stage 11.1では、`node_lease_authority.rs`にruntime-only authority、fake可能なmonotonic clock、safe deadline、renewalの旧deadline再確認、demotion latchを実装し、`state_machine.rs`に明示的なauthority-gated Active入口とRecoveryPending cleanup入口を追加した。Stage 11.2では、同じmodule内の`NodeAuthorityController`が`NodeLeaseAuthority`、trusted `NodeMutationStore`、recovery blockを単一のruntime ownerとして保持する。controller constructorはprivateで、通常のproduction moduleがownerを再生成できない。controllerは`ZeroResource`、`ResourceOwning`、`Unknown`を内部で管理し、conservativeの新しいownership取得はreconcile済みZeroResource、usable authority、未解決LeaseReleaseなしを同時に要求する。fresh controllerはRecoveryBlockedで開始し、Witness grant/retryだけでは解除されない。各checkpointでauthorityを前後に再検証し、permissionは一回限りのruntime値で、永続化・wire送信・再利用を行わない。validated grant、mutation identity、ownership context、reset境界はauthority moduleとそのtrusted Witness child module内に閉じ、RecoveryReady、release-clear、実resource観測のcreatorはまだ存在しない。authority lossまたは不確実なownershipはconservative modeで不可逆にdemotion要求へ進み、late grant/renewで解除されない。`node_witness_runtime.rs`のcontroller経由renewal pathはStage 10 durable completion後に既存authorityへinstallする。現在のCLIにはlive daemon owner/event loopはなく、実service/VIP/GARP cleanup、実resource observation、scheduler、demotion runtimeへの自動接続は未実装である。

### Stage 11.3 ResourceExecutor contract (design only)

Stage 11.3は、`NodeAuthorityController`とtrusted `ResourceExecutor`の境界を定義する。Stage 11.6Aでは、この境界の内側にLinux専用の`NetworkBackend`を追加する。Stage 11.6BではLinux専用のsystemd `ServiceBackend`を追加する。daemon loopはまだ実装しない。MVPは1 VIP、1 service group、Active/Standbyのままとする。

### Stage 11.7 Linux node runtime composition

Stage 11.7は、Linuxのcomposition root `LinuxNodeRuntime`を追加する。公開TOMLは既存のままとし、Linux固有のconstruction dataである`LinuxPlatformConfig`だけが明示的な絶対`arping` pathを保持する。path検索、shell lookup、既定path、fallbackは行わず、無効なpathではruntime constructionを失敗させる。この値は永続化せず、ProtocolやWitnessへ送らない。

runtimeは`LinuxNetworkBackend`、`LinuxSystemdServiceBackend`、既存の`ResourceExecutor`、`ResourceWorkflow`、`NodeAuthorityController`、`NodeMutationStore`を接続する。操作はinitialize/recover、明示的promote、明示的demote、read-only statusに限り、daemon loop、heartbeat loop、automatic promotion/failover、peer failure detectorは持たない。ResourceWorkflowが既存のpromotion/demotion順序、trusted observation、authority checkpoint、cleanup provenance、LeaseRelease境界を所有し、runtimeはActiveやStandbyを直接設定しない。Recovery中のlocal cleanupも同じWorkflowのStopService→確認→ReleaseVIP→確認経路を使用し、Witness authorityを取得しない。statusはVIP/serviceの受動的観測だけを行い、任意の`health.command`は実行せずhealthをUnknownとして扱う。

起動・再起動ではruntime authorityを復元せず、persisted Active、VIP Present、service Running、古いoperation_id、古いlease metadataからActiveを推論しない。VIP Absentかつservice Stoppedで、未解決mutationがなく、その他のRecovery blockerもない場合だけzero-resource reconciliationを成立させてStableな非所有状態へ進む。resourceが残る場合はRecoveryPendingからauthority-free cleanupを試み、Service StoppedとVIP Absentの両方を確認できた場合だけreconcileを再評価する。Unknown、cleanup失敗、未解決LeaseRelease、その他のRecovery blockerはRecoveryPending等のfail-closed状態に留め、fresh LeaseRequestを許可しない。fencingはなく、paused/partitionedな旧Activeの排除やsplit-brainの完全防止は保証しない。

### Stage 11.6A Linux NetworkBackend

`LinuxNetworkBackend`は、設定済みの単一IPv4 VIPとinterfaceを対象に、VIPのadd/delete/observeを同期netlinkで実行する。kernelから取得したinterface/address/prefixの状態がVIPの唯一のlocal resource observationであり、netlink actionのacknowledgementはPresent/Absentを証明しない。interface解決、netlink query、または応答解釈に失敗した場合の観測はUnknownであり、Absentへ変換しない。VIP identityはIPv4 address、interface identity、prefix lengthの組で比較する。

GARPは設定済みの絶対pathの外部`arping`をshellなしで直接起動し、`-U -I <interface> -c <count> <VIP>`を渡す。timeoutは3秒、exit code 0だけを成功とし、non-zero、signal、spawn/wait failure、timeoutは失敗とする。timeoutまたはwait failure時はkill/wait結果を確認し、reapまで確認できない場合はcleanup uncertaintyとして扱う。GARP結果はVIP observation、service、authority、Activeを証明しない。自動retryや`ip`等のfallback commandは行わない。

IPv4 address observationでは`IFA_LOCAL`をlocal identityとして優先し、`IFA_ADDRESS`はpeer addressになり得るため上書きしない。`IFA_LOCAL`がない場合の`IFA_ADDRESS`単独は、他の属性と矛盾しないaddress-only形式としてのみfallbackする。interface indexが異なるaddress entryは対象VIPの判定から除外し、対象interfaceのmalformed/ambiguous entryはUnknownとする。netlink requestには非ゼロのsequenceを割り当て、kernel sender、sequence、multipartのDoneを検証してから観測を完了する。

`LinuxNetworkBackend`はResourceExecutorへraw action/observationだけを返し、NodeState、ownership、authority、Workflow、Witness leaseを変更しない。NetworkBackendのsealed provenanceは維持され、任意のproduction moduleが新しいbackendを実装することはできない。設定型はbackend constructor境界に閉じ、グローバル設定スキーマを拡張しない。実netlink・GARPの特権統合確認はLinux VMまたはContainer Machineで別途行い、macOSのunit test結果を実Linuxの証明とは扱わない。

### Stage 11.6B Linux systemd ServiceBackend

`LinuxSystemdServiceBackend`は、shellを介さず絶対pathの`systemctl`を直接起動し、`start`/`stop`のaction diagnosticと、`systemctl show`によるservice observationを分離する。serviceは`LoadState=loaded`かつ`ActiveState=active, SubState=running`の場合だけRunning、`LoadState=loaded`かつ`ActiveState=inactive, SubState=dead`の場合だけStoppedとし、それ以外の状態、unit不在、malformed/duplicate/query failureはUnknownとして扱う。action成功だけではRunning/Stoppedを証明せず、観測もaction diagnosticを上書きしない。

Stage 11.6Bの明示的なbackend契約として、systemd ServiceBackendは既存設定の`health.command`をhealth observationのためにshellなしで直接argv実行する。health commandのstdoutは解釈せず、保持もしない。exit 0をHealthy、non-zeroをUnhealthy、spawn/timeoutをUnknownとする。healthはservice停止やresource cleanupを証明しない。action timeoutではchildにSIGKILL（systemd backendにTERM/graceはない）を送り、`try_wait`を最大2秒ポーリングしてreapを確認する。期限以降に初めて観測された子の終了は成功ではなくtimeoutとして扱う。reapを確認できない子、またはwaitの問い合わせ自体が失敗した子（後者にはシグナルを送らない）は保持し、解消するまで以後のコマンド（action、`systemctl show`、health）を起動しない。`systemctl show`のstdoutは非ブロッキングpipeを呼び出しスレッドが読み、子の終了とpipeのEOFを別々に判定する。子が終了してもpipeが期限までEOFにならない場合（子以外のプロセスが書き込み側を保持）は出力を不完全として扱い、`Running`/`Stopped`を読み取らない。reader threadは存在せず、pipeの読み取り側は呼び出しの終了時に閉じる。timeout後のservice/health observationは独立して取得する。backendはResourceExecutorへraw結果だけを返し、NodeState、authority、ownership、Workflow、Witness leaseを変更しない。実systemd統合、daemon loop、automatic failover、実HA resource operation、fencingは未実装である。

### Stage 11.8 daemon/runtime loop foundation

Stage 11.8では、`DaemonRuntime`境界の上に小さなdeterministic daemon supervisorを追加する。supervisorはLinuxNodeRuntimeを所有し、startup/recovery、caller駆動のbounded observation tick、shutdown intent、cached snapshotを管理する。tickは観測だけを行い、lease acquire/renew、promotion、demotion、GARP、cleanup、Witness mutation、peer failure判定を暗黙に実行しない。`observation != decision`を維持し、heartbeat欠落をpeer deadとは扱わない。

### Stage 11.9 peer observation foundation

既存Protocol v1のHeartbeat、HELLO/session、HMAC、sequence/replay契約を再利用し、`PeerObserver`は上流session runtimeが確立済みと通知したHeartbeatだけを静的に設定された1 peerの固定slotへ観測する。Heartbeatの認証はsession establishmentそのものではなく、Heartbeat内のsession_idだけではsession切替やreplay window resetを行わない。cluster_id、local/peer node identity、message kind、現在確立済みsessionとの一致、同一session内の単調sequenceを検証する。wrong identity、未確立session、malformed、authentication failure、duplicate/older sequenceは観測を更新せず、固定のInvalid/Unavailable状態へ分類する。

peer observationは`NeverSeen / Fresh / Stale / Invalid / Unavailable`を持つruntime-only cacheであり、freshnessはlocal monotonic-relative receive時刻とheartbeat freshness timeoutで判定する。新sessionは上流のsession establishment通知後にだけsequence windowを切り替え、その瞬間に旧sessionのHeartbeat観測とfreshness基準を無効化して`NeverSeen`相当へ戻す。切替後の旧session Heartbeatは受理しない。同一sessionの重複establishment通知ではFresh観測、last_received、sequence windowをリセットしない。session provenanceはruntime-onlyで、再起動時に復元しない。Stale、NeverSeen、Invalid、Unavailableはいずれもpeer deadを意味しない。remote NodeStateやresource情報は診断的なpeer-reported observationであり、authority、local resource truth、lease、fencingの証明ではない。

Daemonのcaller-driven tickにはpeer observation hookだけを追加し、peer cacheの更新をtick内に限定する。snapshot/statusはpeer送受信、handshake、reconnect、sequence mutation、cache mutationを行わない。peer tickの失敗はdaemonのFailedやpromotion/demotion/lease mutationへ接続しない。Stage 11.9ではtransport実装を認証済みイベント境界とdeterministic fake transportに限定し、real UDP、automatic retry、automatic failover、quorum、fencingは実装しない。

### Stage 11.10 connection/session runtime integration

Stage 11.10は、Protocol v1の既存HELLO/session/HMAC/replay処理とPeerObserverの境界を、deterministic fake connection/session harnessで接続する。session runtimeは`Disconnected / HelloPending / Established / Invalid`の小さな状態を持ち、`AuthenticatedMessage`を既存`PeerSession`へ渡してcluster、peer/local identity、protocol、HELLO priority、session ownership、strict sequenceを検証する。HELLO完了後だけ`SessionEstablished(session_id)`を生成し、heartbeatは`EstablishedHeartbeat`としてのみPeerObserverへ渡す。heartbeat単独、任意のsession_id、接続確立だけではPeerObserverをestablishしない。

新しい認証済みHELLOが受理された場合は、古いsessionのHeartbeat観測を無効化してから新sessionを現在値とし、新sessionの最初のheartbeatまでFreshにしない。duplicate same-session HELLOは再establishせず、既存のFresh、last_received、sequence high-waterをリセットしない。古いconnectionからの遅延heartbeat/session event、wrong identity、protocol/authentication/malformed入力は現在sessionを更新しない。connection lossはDead、promotion、demotion、lease、fencingの証明ではなく、観測上は必要に応じてUnavailableへ分類するだけである。再接続だけではFreshにならず、新HELLOとその後の有効heartbeatを要求する。

session runtimeとPeerObserverはHA判断、resource操作、lease mutationを行わず、daemonからcaller-drivenに駆動できる純粋なruntime boundaryに留める。session_idはProcessSessionの既存寿命、logical mutation retryは既存のrequest_id/mutation_generation契約に従う。Stage 11.10ではproduction socket/accept loop/automatic reconnect、実HA failover、fencing、real resource operationは実装しない。固定peer identity、bounded current connection/session、deterministic fake harnessでのみ検証する。

`connection_id`はopaqueなconnection identityであり、freshness/order authorityではない。current connectionの置換には、local connection manager/runtimeが発行する`ConnectionGeneration`を使用する。generationはwire fieldでもpeer由来のauthorityでもなく、runtime-onlyでchecked incrementされるbounded provenanceである。新しいgenerationだけがcurrent connectionを`HelloPending`へ置換でき、同じgenerationかつ同じconnection_idのConnectはidempotent no-op、同じgenerationで異なるidentityは拒否する。古いgenerationのConnect、HELLO、Heartbeat、Disconnect、malformed/authentication diagnosticはcurrent session、Fresh観測、sequence high-waterへ作用しない。generationは再起動時に永続化・復元せず、新runtimeで再発行する。

startupは既存のinitialize/recoverとreconcileを通過し、`Standby`、recovery reconciled、未解決mutationなし、`resource_owning == false`、VIPが`Absent`、serviceが`Stopped`を同時に確認できた場合だけ通常loopへ進む。`RecoveryPending`、`Unknown`、resource ownership、未解決mutation、その他のrecovery blockerは`RecoveryBlocked`としてloopを開始しない。persisted Active、operation、lease metadata、cached observationからruntime authorityを復元しない。

healthはdaemon observation tickでのみ能動観測し、結果をruntime-owned cacheへ保存する。snapshot/statusはcacheを読むだけで、health commandやresource mutationを実行しない。観測失敗は`Unknown`へ倒し、HealthyやAbsentへ楽観変換しない。snapshot取得はside-effect-freeである。

shutdownはsignal handlerでresource操作を行わず、shutdown intentをnormal runtime contextへ渡す。`Active`または`resource_owning == true`の場合は、VIPとserviceが既にZeroResourceでもshortcutせず、既存のdemotionまたはauthority-free cleanup pathを通過し、cleanup obligation解消とtrustedなVIP `Absent`かつservice `Stopped`を再確認する。`Active`では既存の`StopService → ConfirmServiceStopped → ReleaseVIP → ConfirmVIPReleased → ReleaseLease → CommitStandby`順序を再利用する。`Active`でなくresource ownershipもない場合だけ、trustedなVIP `Absent`かつservice `Stopped`のZeroResource shortcutでclean stopできる。所有中、VIP/serviceが`Unknown`、またはcleanup確認不能の場合は`ShutdownBlocked`としてclean Standbyを報告しない。`Active`かつ`resource_owning == false`というfatal observation invariantは`Failed`へラッチし、通常の観測エラーは`Unknown`に留める。`RecoveryBlocked`でもshutdown intentは`ShutdownRequested`へ遷移し、安全なshutdown判定を通過するまで失われない。Stage 11.8はautomatic HA decision、daemon accept loop、heartbeat loop、fencing、watchdog、実LinuxHAを実装しない。

外部操作は常に`action request → local observation → trusted classification → controller completion`の順に扱う。各操作では、(1) action/diagnostic outcome（success、error、timeout、interrupted）、(2) trusted resource observation、(3) promotion/cleanup workflow decisionを分離する。diagnostic outcomeはtrusted observationを上書きしない。commandのexit statusは診断情報と観測開始の判断に使えるが、観測が必要なresourceの存在・不在を単独で証明しない。

観測の最小語彙はresourceごとに保持する。VIPは`Present / Absent / Unknown`、serviceは`Running / Stopped / Unknown`、healthは`Healthy / Unhealthy / Unknown`、GARPは`Succeeded / Failed`とする。`Unknown`はエラー文字列やboolで代用せず、timeout、signal、観測不能、途中中断を含む不確実性を表す。確認済みのresource factはprivate/sealedなexecutor-controller境界だけが生成し、一般callerは`ZeroResource`、`ResourceOwning`、`Unknown`やconfirmed observationを作れない。

promotion、ownership acquisition、continued ownership / Active progressionの各resource stepは、`checkpoint(X) → one-shot permission → exactly one immediate operation X → trusted observation → complete_checkpoint(permission, X, observation)`で実行する。1つのpermissionでVIP、service、health、GARPを連続実行してはならない。Stage 11.2のcompletion validationが失敗した場合、ownership-acquiring operation後はZeroResourceを維持せずUnknownとdemotion requirementへ進む。local demotion、cleanup、rollback、reconciliationはStage 11.2のpromotion permissionを要求せず、`cleanup operation → trusted observation → existing cleanup/state-machine progression`で実行する。Witness unavailable、lease expired、authority lost、demotion latch、RecoveryBlockedでも、許可されたlocal cleanupを阻止しない。

ZeroResourceは、VIPがAbsent、serviceがStoppedであることをtrusted local observationまたはreconciliationで確認した場合だけ成立する。`ResourceOwning/Unknown → ZeroResource`には両resourceの確認が必要で、caller assertion、command failure、LeaseRelease success、health failureでは遷移しない。GARPはresource ownershipを持たない。VIPまたはserviceのいずれかがUnknownならUnknownを維持し、clean Standbyをcommitしない。

VIP acquireはnetlink add後にVIPを観測する。diagnosticがerror/timeoutでもtrusted observationがPresentならresource truthはPresent、AbsentならAbsentであり、diagnosticは別に保持する。timeout・中断は単独ではresource truthを決めず、trusted observationが得られない場合だけUnknownとする。Presentの場合、意図したVIPが意図したlocal targetにあること、Stage 11.2 authority guard/completion、その他のfatal backend条件を別々に確認し、異常操作を理由とする継続可否を決める。authorityがadd前後に失われた場合はpromotionを継続せず、authority permissionなしでcleanupへ進む。VIP releaseもdelete後のtrusted observationを優先し、error/timeoutでもAbsentなら解放確認として次のcleanupへ進める。PresentまたはUnknownならStandby commitを許可しない。

ServiceBackendはstart/stop要求後に状態を観測する。systemdはunitのrunning/inactive相当を確認する。diagnosticがerror/timeoutでもtrusted observationがRunning/Stoppedならservice truthはその観測を保持し、観測不能時だけUnknownとする。service start error/timeout + trusted Runningはservice truthをRunningとするが、異常なstart actionをpromotion failureとしてrollback/cleanupする。service stop error/timeout + trusted Stoppedは、required postconditionが証明されるためordered cleanupを次の段階へ進められる。command backendでは、旧契約の「stop exit 0 + health check非正常」をStage 11.3で安全上訂正する。この組合せはstop action成功とreadiness非正常を示すだけで、process absence、service ownership absence、ConfirmedStopped、ZeroResourceを証明しない。generic command backendにtrustedな停止観測手段がなければservice observationはUnknownのままで、ConfirmServiceStoppedを越えてVIP解放またはStandbyへ進めない。healthはreadiness evidenceであり、VIP absentやservice stoppedの証明ではない。generic process supervisionはStage 11.3の対象外である。

GARPは既存契約を維持する。IPv4、既知の絶対pathのexternal `arping`、`-U`相当、`-I`、`-c`、VIP、timeout 3秒、exit 0だけを成功とする。GARPはhealth後、Active commit前に実行する。失敗・timeout・signalはpromotion failureとrollbackを開始するが、VIP absentを意味しない。

Active commitには、VIP Present、service Running、health Healthy、GARP Succeeded、fresh `BeforeActiveCommit` permission、successful completion validationをすべて要求する。backendはNodeState::Activeを直接設定しない。demotionは`StopService → ConfirmServiceStopped → ReleaseVIP → ConfirmVIPReleased → ReleaseLease → CommitStandby`の順序を維持する。service stopをStoppedとして確認できない場合はReleaseVIPへ進まず、既存state-machine契約に従いcleanup confirmation failureとしてNodeState::Failed、resource truthは実際のRunningまたはUnknown、ZeroResource/CommitStandbyは禁止とする。後続の明示的recovery/reconciliationで再観測する。local cleanupはWitness authorityや成功したnetwork LeaseReleaseを必要としないが、LeaseReleaseの順序はconfirmed local cleanupの後であり、LeaseRelease successはlocal resource absenceを証明しない。

promotion rollbackはcommand履歴ではなく、最後に得たtrusted observationとUnknownの可能性から開始点を決める。VIP取得後のservice start failure、service running後のhealth failure、health後のGARP failure、authority loss、completion failureはいずれもresourcesが残る可能性を前提に、authority permissionなしでcleanup/reconcileする。cleanup confirmation failureは直ちにNodeState::Failedであり、RecoveryPendingは後続の再起動・明示的recoveryで実リソースを再観測する状態である。プロセス再起動後はRecoveryPendingで開始し、persisted OperationPhase、runtime permission、runtime authority、未完了observationを信用せず、実VIP/serviceを再観測する。RecoveryBlocked解除は将来のtrusted local reconciliationだけが行われ、Witness success、peer state、workflow state、public boolean setterでは解除しない。

将来のNetworkBackendはVIP acquire/observe/releaseとGARPを担当し、ServiceBackendはsystemdまたはcommandのstart/observe/stop/observeを担当する。どちらもcluster authority、lease validity、Active/Standby、RecoveryBlocked、ownership stateを決めない。generic resource-agent、OCF、plugin ABI、dependency graph、async workflow engineは導入しない。

Stage 11.3 failure matrix:

| operation/result | trusted classification | next action |
|---|---|---|
| VIP add success + Present | VIP Present | continue after fresh authority check |
| VIP add error + Present | VIP Present | continue only through authority gate; retain ownership |
| VIP add success + Absent | VIP Absent, acquire unsuccessful | rollback/retry; no Active |
| VIP add timeout + trusted Present | diagnostic Timeout; VIP Present | promotion decision is separate; continue only with intended-target observation and all authority/fatal-condition gates |
| VIP add timeout + trusted Absent | diagnostic Timeout; VIP Absent | acquire unsuccessful; no Active; cleanup decision |
| VIP add timeout + observation unavailable | diagnostic Timeout; VIP Unknown | cleanup/reconcile; no ZeroResource/Active |
| service start success + Running | Service Running | continue after authority check |
| service start error/timeout + trusted Running | diagnostic Error/Timeout; Service Running | promotion fails; rollback/cleanup |
| service start success + Stopped | Service Stopped | promotion fails |
| service start timeout + no trusted observation | diagnostic Timeout; Service Unknown | promotion fails; cleanup/reconcile |
| health failure while resources may exist | Unhealthy, resource truth unchanged | rollback/demotion |
| GARP timeout | GARP Failed, VIP truth unchanged | rollback/cleanup |
| authority loss after VIP/service/before GARP/ before Active | authority unusable | stop promotion; cleanup without Stage 11.2 permission |
| service stop success + Stopped | Service Stopped | continue to VIP release |
| service stop error/timeout + trusted Stopped | diagnostic Error/Timeout; Service Stopped | ConfirmServiceStopped is satisfied; continue ordered cleanup; retain diagnostic |
| service stop success + Running | diagnostic Success; Service Running | ConfirmServiceStopped fails; NodeState Failed; no VIP release/no Standby |
| service stop timeout + no trusted observation | diagnostic Timeout; Service Unknown | ConfirmServiceStopped fails; NodeState Failed; no VIP release/no Standby |
| VIP delete success + Absent | VIP Absent | continue cleanup |
| VIP delete error/timeout + trusted Absent | diagnostic Error/Timeout; VIP Absent | ConfirmVIPReleased is satisfied; continue ordered cleanup; retain diagnostic |
| VIP delete success + Present | diagnostic Success; VIP Present | ConfirmVIPReleased fails; NodeState Failed; no LeaseRelease/Standby |
| VIP delete timeout + no trusted observation | diagnostic Timeout; VIP Unknown | no Standby; recovery required |
| crash between action and observation | Unknown until restart reconciliation | RecoveryPending |
| crash after observation before completion | observation/permission discarded | RecoveryPending re-observation |
| LeaseRelease success while local cleanup uncertain | lease result only | local cleanup/reconciliation continues |
| availability restart with residual resources | local resource state unchanged | no automatic ZeroResource/Standby |

### Stage 11.11 real TCP transport foundation

`TcpPeerRuntime` は既存の4-byte big-endian length prefixと16 KiBの最大payload契約を維持し、listener、connect、現在のsocket、部分frameのpoll、ローカルで割り当てた`ConnectionGeneration`を管理する。accept/connectはTCP接続を`HelloPending`へ届けるだけで、TCP接続自体を認証済みsessionやHA authorityとは扱わない。Node IDのcanonical orderingでdial/listen側を固定し、非canonicalな接続は採用しない。

部分prefix/payloadは接続単位で保持し、同一read内の複数frameは分離する。oversized、malformed、truncated frameはboundedに拒否し、nonblocking pollの`NoEvent`、EOF、transport errorは診断イベントとしてcallerへ返す。これらはpeer dead、lease失効、promotion、demotion、fencingを意味しない。

認証済みwire messageだけを`ConnectionToken`付きで既存の`SessionRuntime`へ渡す。HELLO/HELLO_ACK送信、session event処理、再接続、heartbeat schedulingはcaller駆動であり、transport層は直接`PeerObserver`、HA state、resource、Witnessを変更しない。status相当の参照はsocket I/Oを行わない。自動reconnect、automatic failover、real resource operation、fencing、TLSは本段階の対象外である。

### Stage 11.11 terminal transport failure correction

`WouldBlock`、`NoFrame`、未完了frameのpollはnon-terminalであり、current connectionとsessionを維持する。EOF、partial frameのtruncated EOF、oversized/framing error、fatal read error、fatal write errorはterminalとして扱い、current socketと接続単位のframe bufferをdetach/dropする。terminal failure後は壊れたsocketをcurrentとして再利用せず、caller-drivenな次の`poll_session`で同じ`ConnectionToken`のDisconnectを論理的に一度だけSessionRuntimeへ通知する。pending通知が残る間は新しいconnectionをinstallせず、自動reconnectもしない。

このteardownはTransportUnavailableの診断・session teardownであり、peer dead、FreshからDeadへの判定、lease失効、promotion、demotion、fencingを意味しない。古いsocketのfailureはgenerationとconnection identityがcurrentと一致しない限り新しいcurrent connectionへ影響しない。status/snapshotはpending teardownを処理せず、socket I/Oやgeneration allocationも行わない。

送信時のmessage preparation failureはtransport failureと分離する。`Protocol` validation、local signing/authentication、serialization、frame encodingなどsocket write前のエラーはcallerへ返すだけで、current socket、session、freshness、pending Disconnectを変更しない。実際のsocket I/O errorまたはpartial write後の継続不能なI/O errorだけがterminal write failureとしてsocketをdetachし、既存のexactly-once Disconnect経路へ渡る。どちらの分類もpeer dead、HA action、lease、promotion、demotion、fencingを発生させない。

### Stage 11.12 daemon/TCP runtime composition

`Daemon`のcaller-driven tickから、既存のLinux local observationに続けて`DaemonPeerRuntime`をboundedに駆動する。peer runtimeは`TcpPeerRuntime`、`SessionRuntime`、`PeerObserver`を小さく合成し、canonical Node ID orderingに従うinbound listenerまたはoutbound initial connectを構築する。初回connect失敗はpeer transport unavailableとして扱い、local recovery gateを迂回せずdaemon startupを不必要にfatalへしない。Stage 11.12ではinitial connectと明示的tickまでを対象とし、Stage 12.1でcaller-drivenのbounded reconnect/rebindを追加した。

TCP接続後は既存ProcessSession、serializer、authenticatorでHELLOを送信し、受信側は既存SessionRuntimeへHELLOを渡す。HELLO_ACKとheartbeatの検証が完了するまでPeerObserverをFreshにしない。認証済みheartbeatだけをPeerObserverへ渡し、heartbeat ACKは別のFresh証明にしない。heartbeatはmonotonicなcaller tick時刻と小さいintervalで送信し、lease renewalやHA authorityとは別物である。

1 tickで処理するpeer frame数には`MAX_FRAMES_PER_TICK`の上限を設ける。NoEvent、connection loss、authentication/protocol failure、pending Disconnectは各tickのbounded処理で診断・観測へ変換するだけで、peer Dead、promotion、demotion、lease acquire、resource mutation、fencingを開始しない。terminal transport errorはcurrent socketをdetachし、pending Disconnectをcaller-drivenに一度だけSessionRuntimeへ届ける。

daemon snapshotは保存済みのlocal/peer observationを読むだけで、accept、connect、read、write、HELLO、heartbeat、Disconnect、reconnect、generation allocationを実行しない。shutdownではlocal resource demotion/cleanupを先に完了判定し、その後にpeer transportを閉じる。TCP closeはsafe demotionやresource cleanupの証明ではなく、network failureでlocal cleanupを省略しない。connection/session/Freshはruntime-onlyであり、Protocol v1、Node/Witness persistence、journal/watermarkは変更しない。

terminal write failureでは`TcpPeerRuntime`がcurrent socketをdetachし、pending Disconnectを所有する。daemon側のcurrent token cacheが先に消えても、次のcaller-driven peer tickはcurrent socketの有無に依存せず下位runtimeのpending Disconnectを一度だけSessionRuntimeへ配送する。配送完了後にだけ新しいconnectionのinstallが可能になり、Stage 12.1のreconnectもこの順序を維持する。Disconnectはpeer deadやHA actionの証明ではない。snapshot/statusはこのpending stateをdrainしない。

Heartbeatの`NodeStatusPayload`は、local runtimeが既に取得してcacheしたdiagnostic snapshotを`DaemonPeerRuntime`へ渡して構築する。peer runtimeはVIP、service、healthを追加観測せず、lease操作、cleanup、HA判断も行わない。`node_state`、`operation_phase`、service、health、VIPのcache値をwire payloadへ反映し、未観測時は`NodeState::Init`と各resourceの`unknown`を使用する。`unknown`をAbsent、Stopped、Healthyへ変換しない。Protocolの二値`Role`は既存のlocal NodeStateから作るdiagnostic表現であり、peer reportはauthority proofではない。remote reportは引き続きpromotion、demotion、lease、resource mutationを開始しない。
### Stage 12.1 transport recovery foundation

Stage 12.1 adds caller-driven transport recovery to `DaemonPeerRuntime`. An
outbound connection failure schedules a bounded exponential reconnect, and an
inbound listener bind/accept failure schedules a bounded rebind. The delay is
250 ms initially, doubles through 4 s, and is capped at 5 s. No background
thread, async runtime, or automatic HA decision is introduced.

Terminal transport failure first detaches the current socket and delivers its
pending `Disconnect` to the session runtime. Only after that delivery may a
new connection be installed. A successful replacement creates a new local
`ConnectionGeneration` and performs a new HELLO exchange; it is not Fresh
until a valid heartbeat for the new session is observed. Stale socket/session
events cannot update the replacement connection. Runtime bind failures are
classified as peer transport Unavailable and retried; configuration errors
remain construction errors. Shutdown closes the listener, clears retry
deadlines, and suppresses all later reconnect/rebind attempts.

This stage remains a transport/liveness boundary only. It does not perform
automatic failover, lease or Witness mutation, resource operations, fencing,
or peer-dead decisions. The retry schedule is caller-driven and observable
for diagnostics; retry state is runtime-only and is not persisted or sent on
the wire. Protocol v1 and Node/Witness persistence formats are unchanged.

An installed TCP connection has a bounded runtime-only handshake deadline of
three seconds. The deadline is attached to the current connection token and
starts when an outbound connection is installed or an inbound connection is
accepted. Only authenticated HELLO/HELLO_ACK session establishment clears it;
partial or irrelevant pre-auth traffic does not extend it. Expiry detaches
the socket, queues the normal caller-driven Disconnect, and returns the
connection to transport recovery. Outbound recovery reuses the existing
backoff; inbound expiry releases the slot without starting an outbound
connect. A successful TCP connect alone does not reset backoff, and handshake
expiry is transport failure only: it is not peer-dead proof, authority loss,
failover permission, or any HA action. A stale token cannot expire a
replacement connection, and shutdown suppresses subsequent recovery.
The deadline uses the same caller-driven monotonic `Instant` as retry
scheduling: automatic reconnect passes its tick time through connection
installation, while the explicit `connect_once` wrapper samples `Instant`
once. Thus a synthetic future tick cannot immediately expire a newly
installed handshake in the same tick.
Transport-failure observations emitted during that tick, including handshake
expiry and pending Disconnect processing, use the same caller-supplied
monotonic time. Deterministic runtime diagnostics therefore do not mix a
fresh wall-clock sample into retry, deadline, or observer processing.

### Stage 12.2 peer failure judgment foundation

`PeerFailureDetector` is a bounded, runtime-only diagnostic assessment owned
by the peer runtime boundary. It reports `Unobserved`, `Healthy`, `Suspect`,
or `CommunicationLost`; the last state means only that authenticated peer
communication evidence has not recovered within the five-second caller-driven
confirmation window. It is not a peer-dead declaration, lease proof,
authority decision, failover permission, fencing result, or resource truth.

The detector starts `Unobserved` and remains there for an unseen peer even if
TCP connection, HELLO establishment, reconnect failure, or time passage is
observed. `Healthy` requires a current authenticated session and a valid,
non-replayed heartbeat accepted by the existing `PeerObserver`. Loss of Fresh
evidence, session loss, or terminal transport failure changes a previously
Healthy peer to `Suspect` at the supplied monotonic tick time. Only a valid
heartbeat for the current session clears `Suspect` or `CommunicationLost`;
TCP reconnect and HELLO establishment alone do not.

Session replacement clears the detector's accepted sequence provenance without
restoring Fresh evidence. If the prior assessment was `Healthy`, a different
session enters a new `Suspect` episode at the supplied time; `Suspect`,
`CommunicationLost`, and `Unobserved` retain their conservative semantics.
Duplicate establishment of the current session is a no-op. Old-session,
replayed, invalid, or wrong-identity input cannot recover the assessment.
The detector itself keeps a bounded monotonic time high-water and rejects
backwards event/tick times before mutating state; equal times are valid.
Assessment timers are advanced only by caller-driven ticks, are reset for each
failure episode, and are not persisted. Restart begins again at `Unobserved`
with no time high-water. Snapshot/status access is read-only. The detector has
no Witness, lease, promotion, demotion, fencing, VIP, or service-operation
path.

### Stage 12.3 Witness reachability and failure evidence fusion

`EvidenceFusion` is a separate, bounded, runtime-only diagnostic layer. It
combines the Stage 12.2 peer assessment with opaque trusted Witness
observations, without polling the Witness or invoking any HA operation. Its
states are `Unproven`, `PeerDegraded`, `CorroboratedLoss`, and
`AmbiguousPartition`; Witness observations are separately classified as
`Unknown`, `Reachable`, `Unavailable`, or `NotReady`.

`Healthy` and `Unobserved` peers remain `Unproven` regardless of Witness
loss. `Suspect` is only `PeerDegraded`. A `CommunicationLost` peer becomes
`CorroboratedLoss` only with a fresh `Reachable` Witness observation; a fresh
`Unavailable` or `NotReady` Witness produces the conservative
`AmbiguousPartition` diagnostic, while unknown or stale evidence remains
`Unproven`. All Witness observation statuses use the same five-second
freshness timeout and caller-driven monotonic clock: exactly five seconds is
fresh, five seconds plus one nanosecond is stale. A new Witness `boot_id`
invalidates prior corroboration as `NotReady` until a genuinely new observation
for the new boot is accepted; replaying the first observation cannot advance it.

`WitnessObservation` has private fields and no public constructor. Stage 12.3
introduced only synthetic test issuance; Stage 12.4 adds the child adapter as the
production issuer for local Unavailable outcomes. Remote Reachable issuance
still requires authenticated/correlated completion and boot provenance.
`WitnessConnection::receive_pending` checks authenticated peer identity/session;
`handle_pending_witness_response` correlates `request_id`, commits sequence and
completes outstanding communication. Its public response observation is not an
opaque completion proof, and `TERM_STATUS` contains term/holder but no boot ID.
It therefore cannot currently mint fusion evidence. No new wire field is added.

Tokens bind a private runtime identity, ordered generation and source observation
`Instant` to the status/boot/term/holder. Fusion retains only identity, generation
and source-time high-waters, not an observation history. Duplicate/older tokens
return `ReplayedObservation` without mutation, including after peer recovery.
Delivery time never replaces source time. Missing/blank boot provenance on
Reachable and foreign-runtime tokens return `InvalidObservation`; backwards call
or source times return `TimeWentBackwards` before mutation. Equal times are valid
for genuinely new observations. Term, holder and boot ID are not sequence IDs.
This is a sealed local consumption boundary, not implemented network replay
protection. An issuer must not remint old results as new observations.

Peer recovery clears the fusion state. Restart begins at `Unproven` without
restoring Witness freshness, boot, term, holder, or time high-water. A new runtime
has a new allocation identity and rejects tokens from an older runtime; tokens
are not serialized, and no cross-process persistent replay guarantee is claimed. Fusion
snapshots are read-only, and backwards event/tick times are rejected before
mutation; equal timestamps are valid. `CorroboratedLoss` is evidence only,
not promotion permission, lease proof, fencing proof, peer-dead proof, or
resource truth. Stage 12.3 does not perform promotion, demotion, lease
mutation, fencing, VIP/service operations, or automatic failover. Protocol v1,
Node/Witness persistence, journal, and watermark formats are unchanged.

### Stage 12.4 current-wire Witness evidence adapter

`evidence_fusion::adapter::WitnessEvidenceAdapter` owns a WitnessConnection,
ProcessSession, authenticator, one GET_TERM outstanding request, one queued token,
and its EvidenceFusion. Nesting the adapter under evidence_fusion preserves private
token construction without exposing a general-purpose production constructor.
It has no reference to a lease/HA/resource owner. Production issuance is restricted
to local `Unavailable` with no boot ID. TERM_STATUS lacks boot_id, so authenticated
success is retained as `Completion::TermStatus`, not Reachable or Unavailable.
GET_TERM permits only TERM_STATUS; remote NotReady issuance is also deferred.
No session/request/node/term value is substituted for a boot ID.

`start_at(now)` sends one GET_TERM using existing send/correlation primitives.
Each `WitnessConnection` owns an opaque local provenance identity for its
connection lifetime. A pending request captures that identity, and a polled
response must carry the same local provenance as well as the matching request_id.
Request IDs combine a fresh 128-bit random adapter namespace with a checked
request counter; this namespace is defense in depth, not the restart-safety
boundary. operation_id remains None. Request generation is separate from
observation generation. Timeout is supplied from `lease.request_timeout_sec`
(no new configuration/default). Zero timeout or unrepresentable deadline is rejected.
`poll_at(now)` consumes at most one framed result, reusing receive() for HMAC and
semantic validation and WitnessConnection for cluster/node/session/high-water
validation. The existing handler correlates request_id and GET_TERM response kind
before sequence commit and completion. Wrong, duplicate, unsolicited and late
responses or a result from an obsolete connection provenance do not complete the
current request or issue evidence. At/after deadline,
poll processes the local timeout first; queued late responses remain invalid.

`tick_at(now)` expires a request when now >= deadline, clears it, and issues exactly
one Unavailable token at that caller time. A terminal EOF/reset/broken pipe or
truncated transport also completes a current request once. Auth/semantic/framing
rejection is not converted to Unavailable; the pending request may independently
time out later. NoFrame/partial input and receive WouldBlock/Interrupted/TimedOut
do not complete it. A failed send is not retried on the same stream; the adapter
becomes failed, emitting evidence only for a classified terminal transport failure.
After terminal transport failure, create a new adapter for a new connection.

Local Unavailable completion increments the checked observation generation once;
TERM_STATUS success and rejected responses do not. Overflow clears the attempt,
fails the adapter closed, and emits no token. A queued token blocks new requests
until `deliver_at(now)` consumes it. Delivery preserves source completion time;
fusion rejection consumes the token without reminting/retrying its completion.
Backwards caller time is rejected before mutation; equal time is allowed. Snapshot
does not send, poll, tick, issue, deliver or mutate fusion. There is no background
loop or internal clock sampling. Caller scheduling and reconnect are not added.

Restart resets requests, counters, results and fusion with a new origin, new
connection provenance and random request namespace. An old response cannot satisfy
a new request solely through request_id equality because its bound connection
provenance differs. Old tokens fail origin validation. No persistent network replay
guarantee is claimed. State
is bounded to one request, one token, counters and one diagnostic result; there is
no result history. Wire, persistence and lease authority contracts are unchanged.

### Stage 12.5 failover eligibility policy

`FailoverEligibilityPolicy` is a pure, caller-driven decision layer between
the existing peer failure assessment, `EvidenceFusion`, and the local
`StateMachine`. It answers only whether this node is eligible to attempt a
future promotion. It never starts promotion, acquires or releases a lease,
changes NodeState, performs resource work, or calls Witness/network APIs.

Conservative eligibility requires all of the following current values:
`PeerFailureAssessment::CommunicationLost`,
`EvidenceFusionState::CorroboratedLoss`, and a local `NodeState::Standby` with
no operation in progress plus an explicit `LocalSafetyReadiness::Safe` value.
`Standby` and `OperationPhase::None` alone do not prove promotion safety. The
readiness value is constructed at one caller-owned runtime observation point
from the daemon-owned shutdown flag, current trusted VIP/service observations,
and the existing controller/runtime truth for recovery, demotion obligations,
the full ownership classification, outstanding mutation, and authority
presence. `Safe` requires `OwnershipClass::ZeroResource`, current VIP
`Absent`, and current service `Stopped`; `ResourceOwning`, `Unknown`, and any
non-clean observation fail closed. Shutdown, blocked or unreconciled recovery,
demotion obligations, uncertain ownership, unresolved resource state, present
authority, and unknown readiness all fail closed.
`Unobserved`, `Healthy`, `Suspect`, `Unproven`, and `AmbiguousPartition` never
produce `Eligible`; ambiguous or inconsistent snapshots fail closed. `Failed`,
`Active`, `Candidate`, `RecoveryPending`, `Maintenance`, unsafe local states,
an in-progress promotion, and an unresolved demotion operation are blocked by
explicit reasons.

The resulting `LocalSafetySnapshot` is point-in-time input, not a permanent
authority or resource proof. External/manual resource drift is detected when
the next snapshot is constructed. A future action consumer must revalidate
its authority and resource preconditions before mutation. The policy stores no
eligibility result and owns no clock. Eligibility is
recomputed from each supplied snapshot, so evidence expiry, peer recovery,
Witness boot-change invalidation, and restart reset eligibility immediately.
Restart begins with the existing `Init`/`Unobserved`/`Unproven` observations and
is therefore ineligible. Status integration remains deferred; any future
status view must stay observational. Availability-mode policy remains deferred.

### Stage 12.6 promotion attempt authorization

`PromotionAttemptAuthorization` is the ephemeral conservative-mode boundary
between a current `Eligible` policy result and a future authority acquisition
attempt. It re-evaluates the supplied current `FailoverEligibilityInput` on
every call and returns `Authorized`, a bounded `Blocked` reason, or an
`Indeterminate` reason. It stores no permission, owns no clock, performs no
I/O, and does not contact Witness or mutate leases, state, VIP, service, or
fencing.

An earlier `Eligible` result is not permission for a later call. Shutdown,
resource drift, authority presence, demotion obligations, active operations,
recovery blockers, peer recovery, evidence expiry, and ambiguous partitions
are evaluated from the current input and therefore block or remain
indeterminate. Stage 11 authority checkpoints remain mandatory inner gates.
Availability-mode authorization and resource promotion orchestration are
deferred to later stages; Stage 12.7 owns the future promotion workflow.

### Stage 12.7 trusted authority-attempt observation foundation

Stage 12.7 adds only a caller-driven observation lifecycle. A new GET_TERM is
started at one monotonic time and is completed by a later poll; only the
authenticated, correlated `Completion::TermStatus` from that request may
provide the observation's term. A stored `fusion.witness_term` is never a
current-term proof. Request generation, request ID, outstanding correlation,
connection provenance, ProcessSession sequencing, deadline, and restart
namespace remain the existing stale-response boundary.

The completion acceptance time is the fixed freshness epoch for evidence
observation; poll time never refreshes it, and a stored historical completion
cannot provide a new observation. A single request generation yields at most
one `Ready` current-term observation (one-shot consumption); another current
term requires a new `begin_observation_at` and a new correlated GET_TERM
completion. A completed local `Unavailable` is a terminal observation, not an
adapter error: a deadline poll and a classified terminal read/reset/EOF
transport failure are both surfaced as `Unavailable` (Timeout or Transport)
and drain the queued local Unavailable token in the same observation poll, so
a later observation is not permanently `Busy`. The timeout case is routed
through the normal completion mutation, so a reported `Unavailable` is always
backed by an evidence token and an incremented observation generation.
Authentication, semantic, protocol, and connection-provenance errors are not
normalized to transport Unavailable; they stay fail-closed with the request
pending or the completion non-`Unavailable`. The Stage 12.4 `poll_at` contract
is unchanged.

The future LinuxDaemonRuntime observation owner must forward the current peer
assessment from its existing `DaemonPeerRuntime` owner at that same time and
must pass the daemon-owned shutdown state into the local safety snapshot, so
an in-progress shutdown fails closed rather than reporting `Safe`. This term
observation does not imply Witness Reachable evidence; Protocol v1 still lacks
the boot ID and remote NotReady proof required by the Stage 12.4 trust rules.
No lease, authority, VIP, service, GARP, fencing, or promotion mutation is
performed in this stage.

The observation/policy boundary is additionally pinned by Architecture Guard
v1 (see [testing.md](testing.md#architecture-guard-v1)): MKM-ARCH-001 keeps the
observation/policy modules from depending on mutation-capable modules, and
MKM-ARCH-002 through MKM-ARCH-005 pin the observation lifecycle (current-term
provenance, failure classes never `Ready`, one `Ready` per generation, and
exactly-once Unavailable delivery). The guard set is intentionally small and
does not prove overall HA safety, fencing behavior, or Linux runtime behavior.

### Stage 12.8a current-term / stored-evidence type hardening

Stage 12.8a hardens the boundary between current-attempt authority evidence and
historical/stored evidence. `CurrentWitnessTerm` is ephemeral current-attempt
authority evidence: it represents the term obtained from the current
authenticated, correlated GET_TERM completion, and can originate only from that
completion for the current request generation. Its fields are private, there is
no general/public constructor, and there is no `From`/`Into` conversion from
`EvidenceFusionSnapshot`; only the observation lifecycle mints it, and its
`observed_at` is the completion acceptance time. It is deliberately neither
`Clone`/`Copy` nor serializable/persistable.

`EvidenceFusionSnapshot::witness_term` and `witness_holder` remain historical
or stored evidence for status/debug/history. `WitnessEvidenceView` is a derived,
term-free and holder-free projection used for policy/status/current-attempt
evaluation; it intentionally excludes `witness_term` and `witness_holder`, so
stored evidence cannot be reused as current authority through the current-attempt
observation. `CurrentAuthorityAttemptObservation` now pairs a
`CurrentWitnessTerm` with a `WitnessEvidenceView` plus peer assessment and local
safety, so the historical term is no longer adjacent to the current attempt.
Stage 11 authority/lease semantics, wire protocol, persistent schemas,
authentication, correlation, and resource behavior are unchanged. This stage
does not implement daemon clock composition, shutdown composition, or
observation-to-policy wiring.

### Stage 12.8b single observation clock / single peer-runtime advance

Stage 12.8b resolves the H-2 composition risk by giving one daemon observation
iteration one authoritative `std::time::Instant`. `Daemon::tick()` samples
`Instant::now()` exactly once and delegates to `Daemon::tick_at(now)`; the
deterministic path is `tick_at`. Within one iteration the peer runtime is
advanced exactly once through `DaemonRuntime::peer_tick_at(now, ...)`, and its
snapshot is read with the same `now` through `DaemonRuntime::peer_snapshot_at(now)`.
No internal clock sampling occurs between the peer advance and the snapshot, so
`peer tick time == peer snapshot time == peer assessment time == observation
iteration time` for one iteration. `DaemonPeerRuntime::tick()`/`tick_at()`
remain available, but the daemon composition path calls `tick_at(authoritative_now)`
directly and never both.

The Witness authority observation path is decoupled from the peer runtime:
`LinuxDaemonRuntime::authority_observation_tick_at` no longer advances (or owns)
`DaemonPeerRuntime`. It consumes a `PeerFailureAssessment` already derived by
the composition root and feeds it to `WitnessEvidenceAdapter::observe_peer_at`.
A peer transport failure therefore updates only peer assessment and cannot abort
Witness classification; a Witness failure updates only Witness observation.
`EvidenceFusion` semantics are unchanged. The authority/lease timing domain
(`SystemMonotonicClock`/`MonotonicTime`) remains a separate Stage 11 domain and
is untouched. This stage remains observation/composition infrastructure: no
promotion, lease acquisition, VIP/service/GARP mutation, Active commit, or
observation-to-resource dependency is added. Shutdown composition is Stage
12.8c; observation-to-eligibility wiring is Stage 12.8d.

### Stage 12.8c authoritative shutdown ownership / immutable iteration context

Stage 12.8c removes the shutdown-composition hazard. `Daemon` remains the single
persistent owner of `shutdown_requested`; `LinuxDaemonRuntime` does not gain a
duplicate shutdown flag. Each iteration derives an immutable
`DaemonIterationContext { now, shutdown_requested }` from Daemon-owned state via
`Daemon::iteration_context(now)`. Its fields are private and that is the only
production constructor, so a caller cannot fabricate an inconsistent shutdown
value. The context carries the Stage 12.8b authoritative observation `now`; no
second clock is sampled. It is ephemeral and is not persisted or serialized.

The Witness authority observation API no longer accepts a raw
`shutdown_requested: bool`. `LinuxDaemonRuntime::authority_observation_tick`
consumes the iteration context plus the already-derived peer assessment; there
is no convenience overload taking a raw bool. Local safety for the current
attempt is built from `context.shutdown_requested()`, so shutdown yields
`LocalSafetyReadiness::ShutdownInProgress` regardless of otherwise healthy local
state or a Ready current Witness term. Consequently, shutdown-in-progress can
never produce `FailoverEligibilityPolicy::Eligible` or
`PromotionAttemptAuthorization::Authorized`.

Shutdown/demotion behavior is unchanged: shutdown iterations continue to use the
existing `runtime.shutdown()` path and do not depend on peer or Witness
availability, nor require a successful GET_TERM before demotion/cleanup.
`Daemon::tick_at` and the Stage 12.8b single-clock/single-peer-advance structure
are intact. `SystemMonotonicClock`/`MonotonicTime` remains a separate Stage 11
domain. This stage adds no promotion/lease/resource mutation and no
observation-to-policy wiring; Stage 12.8d remains deferred.

### Stage 12.8d inert observation -> eligibility -> authorization composition

Stage 12.8d wires the safe observation components into the production
composition and stops at an inert decision. The Linux composition root
(`LinuxDaemonRuntime::evaluate_authority_attempt`) progresses the current
Witness observation using the `DaemonIterationContext` and the peer assessment
already derived for the iteration, then, only when a current correlated term is
`Ready`, produces an `AuthorityAttemptEvaluation`:

```
observation (CurrentAuthorityAttemptObservation)
    -> FailoverEligibilityPolicy::evaluate   (pure, inert)
    -> PromotionAttemptAuthorization::evaluate (pure, inert, fresh)
    -> STOP
```

`AuthorityAttemptEvaluation` is pure data: it holds the observation, the
eligibility value, and the authorization value, and exposes read-only
`is_eligible`/`is_authorized`. It contains no handle to an authority/resource
owner, no `ResourceExecutor`/`ResourceWorkflow`/`NodeAuthorityController`, no
promote/lease/VIP/service/GARP callback, and no method that executes an action.
`AuthorityObservationProgress::into_evaluation` maps
`AwaitingWitnessTerm`/`Unavailable` to `None` (no current attempt), so absence
is explicit and a pending/unavailable/stale/invalid observation can never
become an authorized attempt.

`Ready`, `Eligible`, `Authorized`, and `Promoted` are distinct stages. This stage
never maps `Eligible` to `Authorized` implicitly (authorization is a fresh
re-evaluation) and never acts on `Authorized`. It does not begin a GET_TERM on
each tick (that would change authority semantics); the composition is
caller-driven. Promotion, lease acquisition, VIP/service/GARP mutation, Active
commit, and fencing remain a later explicit path guarded by Stage 11
`AuthorityCheckpoint`; those semantics are unchanged. `Ready != Eligible !=
Authorized != Promoted`.

### Stage 12.8e deterministic failover scenario matrix

Stage 12.8e is a verification stage: it exercises the Stage 12.7/12.8a-d
composition as a coherent decision pipeline with a deterministic, table-driven
matrix (MKM-ARCH-009) plus history-sensitive sequences. It adds no failover
behavior and no production mutation path; production changes for this stage are
test-only helpers.

The matrix maps `(observation state, peer assessment, fused evidence state,
local safety)` through `AuthorityObservationProgress::into_evaluation` to
`AuthorityAttemptEvaluation`, asserting observation presence, eligibility,
authorization, peer/readiness preservation, and a mutation sentinel (zero
calls). It includes one explicit **positive Authorized control**
(`CommunicationLost + CorroboratedLoss + Safe`) so the guard is not vacuous.

Fail-closed categories proven non-Authorized: healthy peer; communication lost
with unproven/degraded evidence; shutdown; Witness unavailable; Witness
awaiting; Witness terminal failure with healthy peer; `Ready` + ambiguous
partition. Pending/Unavailable map to no attempt. `Ready` alone never implies
`Eligible`/`Authorized`, and `Eligible`/`Authorized` never imply mutation.
Sequences cover healthy -> communication loss -> corroborated loss, Ready ->
shutdown override, superseded request generation, and Unavailable -> fresh
independent Ready.

This remains cross-platform deterministic verification. It does **not** prove
Linux runtime behavior (systemd/netlink/GARP/real socket interleaving/real
`LinuxDaemonRuntime` mutation absence); that is Stage 12.8f. Stage 12.8 still has
no promotion execution.

### Stage 12.8f Linux runtime validation of the inert decision composition

Stage 12.8f executes the real `LinuxDaemonRuntime` decision composition on an
actual Linux host to confirm that the Stage 12.8a-e properties hold outside the
fakeless cross-platform tests. It exercises
`LinuxDaemonRuntime::evaluate_authority_attempt` / `authority_observation_tick`
built from the production Linux backends (harmless non-existent interface and
unit names; no VIP/service/GARP/network mutation) with a loopback Witness socket
and a connectionless peer runtime. No root is used: on Linux `Psk::load`
requires a root-owned 0600 file, so the tests inject components through
`#[cfg(test)]`-only constructors (`LinuxDaemonRuntime::new_for_test`) rather than
the production `from_config`, and never call the production PSK path.

Validated on Linux: the no-Witness-adapter path fails closed; the
no-current-term path yields `AwaitingWitnessTerm`/`None` (no attempt); shutdown
yields `ShutdownInProgress` and no attempt; a real correlated GET_TERM over
loopback mints a current term through the production correlation path and yields
`Ready` while remaining **non-Authorized** (the current wire cannot issue
Reachable/`CorroboratedLoss`, and the inert decision path never mutates). Peer
advance is counted at the `DaemonPeerRuntime` boundary: exactly one per
iteration, and Witness/evaluation do not advance it.

Mutation absence: directly proven — no promotion, lease, VIP, service, or GARP
call is reachable from `AuthorityAttemptEvaluation`/`evaluate_authority_attempt`;
the evaluation types hold no such handle, and the Linux test observes zero peer
advances. Structurally prevented — ARCH-001 keeps observation/policy modules
free of mutation-layer imports. Deferred to a later promotion/resource E2E
stage — successful real systemd/VIP/GARP mutation and `LinuxNodeRuntime::promote`
execution. Stage 12.8 ends at inert authorization; `Ready != Eligible !=
Authorized != Promoted`.

### Stage 13.1 promotion attempt lifecycle (inert)

Stage 13.1 adds the minimum lifecycle for one explicit local promotion attempt.
It represents `no attempt -> explicit request accepted -> one attempt in progress
-> completed / cancelled -> no attempt`. It is lifecycle plumbing only: it does
not execute promotion, acquire or mutate a lease, mutate VIP/service/GARP, or
commit Active, and it never stores an `AuthorityAttemptEvaluation`, a
`CurrentWitnessTerm`, a `RuntimeLeaseAuthority`, or an `AuthorityPermission`.

The lifecycle is owned by `Daemon` (the single shutdown-truth owner), not by the
observation/policy types, and is process-local (no persistence/journaling). A
new attempt is rejected while the authoritative `Daemon`-owned shutdown state is
requested; on restart the slot is `Idle`, and existing startup reconciliation
remains responsible for real-resource safety.

`PromotionRequestId` is a local, ephemeral identity distinct from the peer-wire
`OperationId` (whose semantics are promotion/demotion message correlation);
reusing `OperationId` for a local operator attempt would be ambiguous, so Stage
13.1 keeps request identity local. `PromotionExecutionRequest` carries only that
identity; it contains no authorization, term, evidence, lease, permission,
resource handle, or callback. `Authorized` remains an inert decision result and
is never stored for later consumption. Stage 13.2 remains responsible for fresh
revalidation and lease handoff immediately before any mutation.

### Stage 13.2-pre single Witness session ownership

Stage 13.2-pre is a transport-ownership refactor that centralizes the Witness
transport/session state into one neutral owner. `WitnessConnection`,
`ProcessSession`, `MessageAuthenticator`, and the single
`WitnessRequestOutstanding` now live together in `witness_runtime::WitnessSession`.
`WitnessEvidenceAdapter` becomes observation-state-only: it no longer owns any
transport, session, or outstanding state, and its constructor takes only the
request timeout. Transport-touching observation methods borrow the
`WitnessSession` for the duration of one call; no borrow is stored, so there is
no self-referential structure, no `unsafe`, and no `Arc<Mutex>`/`Rc<RefCell>`.

`LinuxDaemonRuntime` is the composition owner of exactly one
`witness_session: Option<WitnessSession>` and one observation-only
`witness_observer`, attached together via `attach_witness`. There is one physical
Witness connection and one outstanding request slot for the logical session.
Observation and future lease operations are intended to share that single slot;
observation and lease requests are serialized (one outstanding at a time), not
multiplexed.

`WitnessSession` is transport/session infrastructure only: it evaluates no
failover policy, holds no `CurrentWitnessTerm`, `AuthorityAttemptEvaluation`,
`PromotionExecutionRequest`, `RuntimeLeaseAuthority`, or `AuthorityPermission`,
and performs no resource mutation.

This stage does not wire lease acquisition/renew/release, does not implement
Witness reconnect, and does not make production `Authorized` reachable. The
currently unwired `NodeWitnessMutationRuntime` builds its own local outstanding
slot today; when Stage 13.2 wires the lease path it must use the shared session
slot rather than introducing a second production slot. Stage 13.2 (fresh
authorization + lease handoff) remains pending.

### Stage 13.2 fresh revalidation + shared Witness lease + attempt-bound promotion

Stage 13.2 is the minimum composition that connects existing components so one
explicit Stage 13.1 promotion attempt can reach the existing Stage 11 mutation
boundary only after fresh revalidation and a fresh attempt-bound lease. It does
not redesign Mikagami and does not introduce a new promotion subsystem.

#### Non-negotiable safety model

```
Ready != Eligible != Authorized != PromotionAttempt != LeaseAuthority != Promoted
```

- `PromotionRequestId` is identity only and never authority.
- `InFlight` never means authorized-to-execute.
- `Authorized` never equals lease authority and is never stored across calls.
- `PromotionExecutionRequest` remains identity-only and is never a bearer
  capability.
- `LeaseAuthority` never equals `Promoted`.
- An earlier state may never substitute for a later one.

#### Stage 13.2 start and end boundary

**Start:** a caller submits `PromotionExecutionRequest` to the Stage 13.1
`Daemon` lifecycle while the slot is `Idle` and shutdown is not requested. The
accepted request becomes `InFlight(PromotionRequestId)` and Stage 13.2 execution
for that attempt begins.

**End:** Stage 13.2 performs actual promotion through the existing Stage 11
checkpoint path (`LinuxNodeRuntime::promote` / `ResourceWorkflow::promote` /
`NodeAuthorityController`) and then retires the attempt. The endpoint is one of:

- `Succeeded` — Stage 11 reached `ReadyForActiveCommit` and Active progression
  completed under existing Stage 11 semantics;
- `BlockedBeforeMutation` — any pre-mutation gate failed and Stage 11 was never
  entered;
- `MutationFailed` — Stage 11 was entered and existing rollback/cleanup
  semantics applied;
- `Cancelled` — the attempt was retired before mutation began.

Rationale for ending at real Stage 11 promotion rather than emitting a deferred
mutation token: Stage 13.1 already defines13.2 as "fresh revalidation and lease
handoff immediately before any mutation"; `LinuxNodeRuntime::promote` already
owns mutation; no later stage exists to consume a deferred token; inventing a
long-lived mutation-authority type would violate the requirement to avoid new
authority storage. Stage 11 remains the sole mutation-authority checkpoint.

#### Production call path

Owner: `Daemon` (shutdown truth + Stage 13.1 lifecycle) driving
`LinuxDaemonRuntime` (WitnessSession + LinuxNodeRuntime + peer). One logical
execution driver method:

`Daemon::execute_promotion_attempt(request: PromotionExecutionRequest) -> PromotionAttemptResult`

Sequence:

```text
caller
  -> Daemon::execute_promotion_attempt(PromotionExecutionRequest)
       1. reject if shutdown_requested                       -> RejectedShutdown
       2. accept into Idle slot or reject AlreadyInProgress
          (Stage 13.1 accept; identity only)
       3. fresh revalidation owner (this call) performs exactly one
          evaluate_authority_attempt(context)
          - Awaiting / Unavailable / LocalSafetyNotReady / Err
              -> BlockedBeforeMutation + cancel/finish retire
          - Ready + !Authorized
              -> BlockedBeforeMutation + retire
          - Ready + Authorized
              -> continue; do NOT store Authorized
       4. lease acquisition through shared WitnessSession
          (NodeWitnessMutationRuntime borrowed against session)
          - non-AcceptedSuccess / error / timeout
              -> BlockedBeforeMutation + lease cleanup + retire
          - AcceptedSuccess -> build attempt-bound LeaseAuthority
       5. final Stage 13.2 checkpoint
          (shutdown, InFlight identity still current, lease usable)
          - fail -> lease cleanup + BlockedBeforeMutation + retire
       6. handoff to existing Stage 11 mutation
          LinuxNodeRuntime::promote()
          - Stage 11 owns rollback/resource cleanup on failure
          - result mapped to Succeeded / MutationFailed
       7. lease cleanup if mutation did not leave Active ownership
          under existing Stage 11 cleanup rules
       8. Daemon::finish_promotion_attempt() retire -> Idle
```

`request_promotion_attempt` / `finish_promotion_attempt` /
`cancel_promotion_attempt` remain Stage 13.1 inert lifecycle APIs. They never
call `authority_observation_tick`, `begin_authority_observation`,
`evaluate_authority_attempt`, or `peer_tick_at`.

#### Fresh revalidation contract

- **Who:** the single Stage 13.2 execution driver (`Daemon::execute_promotion_attempt`)
  is the only fresh-revalidation owner for that attempt.
- **When:** once per execution attempt, after `InFlight` acceptance and before
  lease acquisition.
- **API:** `LinuxDaemonRuntime::evaluate_authority_attempt(DaemonIterationContext)`
  only. The driver must not call `authority_observation_tick` and then
  `evaluate_authority_attempt` for the same logical observation.
- **Success:** `Some(AuthorityAttemptEvaluation)` with `is_authorized() == true`
  from the current call. The evaluation is moved into a short-lived execution
  frame and dropped before Stage 11 mutation completes; it is never stored in
  `PromotionAttemptLifecycle` and never keyed by `PromotionRequestId`.
- **Rejection:** `None`, `Err`, `is_authorized() == false`, or
  `is_eligible() == false` all mean `BlockedBeforeMutation`.
- **Pending:** `AwaitingWitnessTerm` maps to `BlockedBeforeMutation` in Stage
  13.2. There is no multi-tick wait loop inside one execution attempt. A new
  attempt is required.
- **Unavailable / no CurrentWitnessTerm:** same as rejection. Protocol v1
  cannot mint `CorroboratedLoss`; therefore a real composition that remains
  `Unproven` cannot be `Authorized`. That is fail-closed and expected.
- **Forbidden:** any previously stored `Authorized`, any reconstruction from
  `PromotionRequestId`, and any second observation call for one logical
  revalidation.

#### Revalidation / lease ordering

**Order: fresh authorization first, then lease acquisition.**

Reasons grounded in existing machinery:

1. Stage 12.8d already defines observation -> eligibility -> authorization as
   an inert stop. Crossing to Witness mutation (lease) is a later, stronger
   act and must not precede a fresh Authorized decision.
2. Acquiring a lease while ineligible would create unnecessary Witness
   mutations and outstanding-slot occupancy that Stage 13.2 would then have to
   clean up.
3. Stage 11 authority checkpoints already require usable lease authority at
   mutation time; authorization-first narrows lease acquisition to attempts
   that may proceed.
4. WitnessSession has one outstanding slot; authorization uses GET_TERM
   observation through that slot first, then lease uses the same slot. The
   sequence avoids simultaneous observation + lease requests.

#### Shared WitnessSession ownership

Stage 13.2-pre remains binding:

- `LinuxDaemonRuntime` owns exactly one `WitnessSession` and one
  observation-only `witness_observer`.
- `WitnessSession` owns exactly one `WitnessRequestOutstanding` slot.
- Observation and lease traffic share that slot and are strictly serialized.

Stage 13.2 lease wiring:

- `NodeWitnessMutationRuntime` must be adapted to a **state-only mutation
  runtime** whose transport operations **borrow `&mut WitnessSession`** for one
  call. It must not construct a second `WitnessRequestOutstanding`, own a
  `WitnessConnection`, or create a second production session.
- Smallest consistent shape: keep `NodeMutationStore` durable begin/complete
  semantics; replace `execute_outstanding_once(connection, process, auth)` with
  `execute_outstanding_once(session: &mut WitnessSession)` (or equivalent
  borrow) so send/poll/correlation use `WitnessSession`'s single outstanding
  slot.
- Prohibited: second production `WitnessSession`; second production outstanding
  slot; simultaneous observation + lease requests; delivering a completion to
  the wrong consumer; `NodeWitnessMutationRuntime` privately allocating its own
  outstanding slot once wired.

Completion delivery: only the borrower of `&mut WitnessSession` for the current
call may consume the outstanding completion. Observation and lease completions
are never interleaved inside one borrow.

#### Lease acquisition contract

- **Component:** `NodeWitnessMutationRuntime` + `NodeMutationStore`
  `begin_lease_request` / existing Stage 10 execute path, borrowing the shared
  `WitnessSession`.
- **Session:** the single `LinuxDaemonRuntime` `WitnessSession`.
- **Correlation ownership:** `WitnessSession`'s `WitnessRequestOutstanding` and
  Protocol `RequestId` (existing Stage 10/12.4 rules). `PromotionRequestId` is
  not used for wire correlation.
- **Success:** `NodeWitnessMutationResult::AcceptedSuccess` with validated
  grant identity and `lease_remaining_ms`, converted into a fresh
  attempt-bound `LeaseAuthority` via existing Stage 11 timing origin rules
  (`attempt_start + remaining - margin`).
- **Failure:** typed reject, transport error, timeout, semantic mismatch, or
  non-success terminal disposition -> no `LeaseAuthority`, attempt
  `BlockedBeforeMutation`, existing Stage 9/10 outstanding disposition rules
  apply.
- **Timeout / stale / wrong-request completion:** existing Stage 10
  classification. Stale or wrong-request completions never mint
  `LeaseAuthority`.
- **Single-shot per attempt:** yes. One `begin_lease_request` + one successful
  execute completion per Stage 13.2 attempt. No implicit retry inside the
  attempt. Exact retry of a durable outstanding mutation remains the existing
  Stage 10 recovery path and is not Stage 13.2 automatic retry.

#### Lease-to-attempt binding

Binding is **structural move ownership**, not an ID map.

- On `AcceptedSuccess`, the execution driver constructs one
  `AttemptBoundLeaseAuthority` value that holds the existing
  `RuntimeLeaseAuthority` plus the attempt's `PromotionRequestId` for identity
  only.
- That value is created only inside the execution frame for the current
  `InFlight` attempt and is **moved** into the Stage 13.2 final checkpoint and
  then into the Stage 11 handoff.
- There is no `HashMap<PromotionRequestId, Authority>`, no ID -> authority
  lookup, and no cache.
- Attempt A's lease value cannot authorize attempt B because it is not stored
  and cannot be recovered by ID. A cloned or reused `PromotionRequestId` grants
  nothing.
- `PromotionRequestId` inside the bound value is correlation identity only and
  is never exchanged for capability.

#### Authority lifetime

- Fresh authorization is process-local, call-scoped, and not persisted.
- It is not stored in `PromotionAttemptLifecycle`.
- It is not recoverable from `PromotionRequestId`.
- Restart destroys the process-local attempt and all authority frames.
- Attempt-bound lease authority is **consumed by the Stage 11 checkpoint
  handoff** (moved into the execution of `LinuxNodeRuntime::promote` /
  `NodeAuthorityController` path). It is not retained as a reusable authority
  store after the attempt ends.
- If mutation does not begin, the lease value is used only for best-effort
  release cleanup and then dropped.

#### Final pre-mutation checkpoint (Stage 13.2 orchestration)

Immediately before calling Stage 11, the execution driver checks:

1. `Daemon.shutdown_requested == false`
2. current lifecycle is still `InFlight(this PromotionRequestId)`
3. the attempt has not been cancelled/retired
4. the attempt-bound lease authority exists and is usable under existing
   Stage 11 `RuntimeLeaseAuthority` semantics (safe deadline in the future)
5. no second Witness outstanding is in flight

These are **orchestration checks**. They do not duplicate Stage 11
`NodeAuthorityController::checkpoint` / `complete_checkpoint` rules.

**Handoff point:** after checks 1-5 pass, the driver calls the existing Stage 11
mutation path (`LinuxNodeRuntime::promote`). From that call onward, Stage 11
owns resource mutation order, authority checkpoints, rollback, and cleanup
provenance. Stage 13.2 does not reimplement Stage 11.

#### Shutdown race contract

Required outcome for:

1. attempt created
2. fresh revalidation succeeds
3. shutdown requested
4. lease response arrives
5. mutation would otherwise begin

is **NO PROMOTION**. Enforcement: final pre-mutation checkpoint item 1
(`shutdown_requested == false`) fails closed before Stage 11 handoff. The lease
response may be durably completed as history, but no `LeaseAuthority` is handed
to mutation.

| Shutdown timing | Behavior |
|-----------------|----------|
| before revalidation | Stage 13.1 `request_promotion_attempt` rejects new work; if already InFlight, revalidation is not started or fails the final/entry shutdown check |
| while revalidation pending | no Stage 11; retire attempt `BlockedBeforeMutation` or `Cancelled` |
| after authorization | authorization is dropped; no lease mutation required; retire without mutation |
| while lease acquisition pending | do not hand off; attempt-bound lease not installed for mutation; cleanup per lease cleanup contract |
| after lease acquisition, before mutation | final checkpoint fails; lease cleanup; no Stage 11 |
| during mutation after Stage 11 checkpoint | follow existing Stage 11 atomicity/rollback. No arbitrary mid-mutation cancel. |

#### Cancellation contract

| Timing | Behavior |
|--------|----------|
| before revalidation | `cancel_promotion_attempt` retires `InFlight` -> `Idle`; later execute driver sees no matching InFlight |
| during revalidation | same; revalidation result is discarded; no lease |
| after authorization | drop authorization; no lease required; retire |
| during lease acquisition | cannot unsend the request; do not install lease for mutation; after completion, run lease cleanup if a lease exists; retire |
| after lease acquisition | final checkpoint or execute driver observes cancel/retire; lease cleanup; no mutation |
| after Stage 11 mutation has begun | cancellation is no longer a Stage 13.2 stop. Existing Stage 11 mutation/rollback semantics apply. No arbitrary mid-mutation cancellation. |

#### finish/cancel ownership (Stage 13.1 F-02)

Once execution exists, retirement is owned by the **unique execution driver
frame** that consumed the `InFlight` slot:

- `Daemon::execute_promotion_attempt` is the only production entry that
  transitions an accepted request into execution.
- That call holds `&mut Daemon` (or an exclusive execution token derived from
  the current `InFlight` identity) for the duration of the attempt.
- `finish_promotion_attempt` / `cancel_promotion_attempt` used as lifecycle
  primitives from inside that frame retire **only** the attempt the frame
  accepted. External concurrent finish/cancel of a different logical attempt is
  impossible while the slot is single and the driver is exclusive.
- Required invariant: attempt A completion/cancellation never retires attempt B.
  Enforced by: single slot + exclusive execution ownership + identity check at
  the start of the execution frame (`in_flight_id == request.request_id`).

Optional hardening (not required for uniqueness): `finish(id)` /
`cancel(id)` overloads that no-op unless the id matches. The single-owner rule
is the primary mechanism.

#### Retired ID reuse (Stage 13.1 F-03)

Reuse of a retired `PromotionRequestId` remains allowed and harmless under
Stage 13.2 because:

1. no authority is stored by ID;
2. no lease is recovered by ID;
3. old attempt completions cannot affect a new attempt (execution frame is
   exclusive and identity-checked at accept/execute time);
4. Protocol correlation uses Witness `RequestId` / session sequence, which are
   independent of `PromotionRequestId`.

`PromotionRequestId` is not turned into a security token to solve reuse.

#### Lease cleanup / abort contract

When a lease was acquired but mutation does not begin:

- **Explicit release is required as best effort** using the existing
  `begin_lease_release` / Stage 10 execute path when a durable release can be
  started safely.
- **Who:** the same execution driver frame, through
  `NodeWitnessMutationRuntime` borrowing the shared `WitnessSession`.
- **Same session / one slot:** yes. Release occupies the single outstanding
  slot and is serialized after the lease request completes.
- **If release fails:** do not invent success. Leave durable outstanding per
  existing Stage 9/10 rules; local resource safety does not depend on release
  success (Stage 11 invariant S11-I10).
- **Safety backstop:** Witness lease expiry and Node local safe-deadline
  demotion semantics remain the backstop. Stage 13.2 does not extend lease
  lifetime to cover cleanup.
- **Return to Idle:** the promotion attempt is retired to `Idle` after cleanup
  is attempted, even if release is still outstanding.
- **New attempt while cleanup pending:** allowed at the Stage 13.1 lifecycle
  level only if the single Witness outstanding slot is free or the new attempt
  waits for the outstanding release to complete. Simultaneous outstanding
  requests are forbidden. Prefer: reject/defer new execution until the shared
  slot is idle.

#### Mutation failure contract

If Stage 13.2 reaches Stage 11 and promotion fails:

- **Rollback and resource cleanup:** existing `ResourceWorkflow` /
  `LinuxNodeRuntime` Stage 11 semantics. Stage 13.2 does not duplicate rollback.
- **Lease cleanup:** after Stage 11 cleanup path runs, best-effort
  `LeaseRelease` as in existing demotion/cleanup ordering (local cleanup first).
- **Lifecycle retirement:** execution driver retires the attempt
  (`finish_promotion_attempt`) and maps the outcome to `MutationFailed`.
- **Returned result:** `PromotionAttemptResult::MutationFailed` with the
  existing Stage 11 error/outcome. No success is reported.

#### Retry contract

**No implicit retry in Stage 13.2.**

- One execution attempt = one revalidation = one lease request attempt = one
  Stage 11 handoff at most.
- Failure requires a new explicit `PromotionExecutionRequest` after the slot
  returns to `Idle`.
- Exact retry of a durable outstanding Witness mutation remains Stage 10
  recovery and is not Stage 13.2 automatic promotion retry.

#### Restart / persistence contract

- `InFlight` is lost on restart (process-local).
- Fresh authorization and attempt-bound lease frames are lost.
- No authority is reconstructed from `PromotionRequestId`.
- Startup reconciliation remains responsible for actual VIP/service state.
- Witness lease truth and `NodeMutationStore` durable outstanding mutations are
  independent of the process-local promotion attempt slot and follow existing
  persistence contracts.
- Stage 13.2 adds **no** persistence for promotion attempts.

#### Automatic failover boundary

Stage 13.2 does **not** introduce automatic failover. There is no
peer-loss -> promotion wiring, no timer-driven promotion, and no implicit
promotion from observation ticks. Stage 13.2 executes one explicit promotion
attempt only.

#### Type contract

| Type | Module | Authority-bearing? | Clone/Copy | Persistence | Construction | Consumption |
|------|--------|--------------------|------------|-------------|--------------|-------------|
| `PromotionRequestId` | `promotion_attempt` | No (identity) | Clone allowed; grants nothing | None | `new` | Identity checks only |
| `PromotionExecutionRequest` | `promotion_attempt` | No | No | None | `new(id)` | Execute driver accept |
| `PromotionAttemptLifecycle` | `promotion_attempt` | No | Clone of inert state | None | `idle()` | accept/finish/cancel |
| `AuthorityAttemptEvaluation` | `daemon` (existing) | Inert decision data | No | None | `into_evaluation` | Dropped after decision |
| `AttemptBoundLeaseAuthority` | `daemon` or `promotion_attempt` (new, narrow) | **Yes — lease authority** | **No Clone/Copy** | None | only after `AcceptedSuccess` inside execute driver | Moved into Stage 11 handoff or release cleanup, then dropped |
| `PromotionAttemptResult` | `promotion_attempt` (new, inert result) | No | No | None | execute driver | Caller |

`AttemptBoundLeaseAuthority` non-forgeability: private fields; constructed only
by the Stage 13.2 execute driver from `AcceptedSuccess` + existing
`RuntimeLeaseAuthority` timing rules; no public constructor; no `From` from IDs
or stored evidence.

#### Decision table

| InFlight | Fresh Authorized | Lease | Shutdown | Attempt matches | Result |
|----------|------------------|-------|----------|-----------------|--------|
| no | n/a | n/a | n/a | n/a | no mutation (`Rejected`/`AlreadyIdle`) |
| yes | no | n/a | no | yes | no mutation (`BlockedBeforeMutation`) |
| yes | yes | no | no | yes | no mutation (`BlockedBeforeMutation`) |
| yes | yes | yes | yes | yes | no mutation (`BlockedBeforeMutation` + lease cleanup) |
| yes | yes | yes | no | no | no mutation (`BlockedBeforeMutation` + lease cleanup) |
| yes | yes | yes | no | yes | Stage 11 handoff (`Succeeded` / `MutationFailed`) |

#### Sequence

```text
caller
  | PromotionExecutionRequest
  v
Daemon (lifecycle + shutdown truth)
  | accept InFlight(id)                    // Stage 13.1
  v
LinuxDaemonRuntime::evaluate_authority_attempt(ctx)   // exactly once
  | Ready + Authorized
  v
NodeWitnessMutationRuntime + WitnessSession (shared outstanding)
  | begin_lease_request + execute once
  | AcceptedSuccess
  v
AttemptBoundLeaseAuthority { RuntimeLeaseAuthority + id }
  |
  v
final Stage 13.2 checkpoint
  (shutdown, InFlight(id) still current, lease usable)
  |
  v
LinuxNodeRuntime::promote / ResourceWorkflow / NodeAuthorityController
  | Stage 11 checkpoints + resource mutation
  v
PromotionAttemptResult
  |
  v
Daemon::finish_promotion_attempt() -> Idle
  (+ lease release cleanup if not Active-owned)
```

#### What Stage 13.2 does not do

- no automatic failover
- no persistence of promotion attempts
- no reusable authorization cache
- no second Witness session
- no second outstanding request slot
- no protocol redesign
- no CLI redesign
- no Witness reconnect implementation
- no unrelated demotion redesign
- no arbitrary mid-mutation cancellation
- no change to Stage 11 checkpoint semantics
- no fencing introduction

### Stage 13.3 authority-view evidence path (design, remediated)

This section supersedes the initial Stage 13.3 Quorum-View wording.

#### Explicit non-claims

Stage 13.3 does **not** claim:

- the Witness observes peer liveness
- GET_TERM success proves the peer is dead
- `holder = None` proves the peer stopped serving or released resources
- `safe_deadline` is external fencing
- authorization itself may activate resources

#### Authorization semantics

`PromotionAttemptAuthorization::Authorized` means only:

> Fresh policy evidence permits this node to enter the mandatory fresh
> lease-authority acquisition phase (Stage 13.2).

It does **not** mean peer death, resource shutdown, lease ownership,
completed fencing, or permission to mutate. Stage 11 remains the only
resource-mutation boundary.

#### Two evidence axes (facts, not conclusions)

1. **Local axis — fresh communication-loss evidence**
   `PeerFailureAssessment::CommunicationLost` plus an objective freshness
   bound (see below). This proves only that this node currently cannot
   communicate with the peer.
2. **Authority axis — fresh Witness authority-view evidence**
   Authenticated, correlated `TermStatus` from the current observation
   cycle, classified as `AuthorityViewCompatible` only when the Witness
   records no conflicting authoritative holder (see holder contracts).

Together these may satisfy policy to **attempt lease acquisition**. They
never prove peer death and never permit direct resource activation.

#### Naming (implementation contract)

| Misleading name | Required semantic name |
|-----------------|------------------------|
| authorization-relevant `WitnessStatus::Reachable` | `WitnessStatus::AuthorityViewCompatible` |
| `EvidenceFusionState::CorroboratedLoss` | `EvidenceFusionState::FailoverEvidenceReady` |
| synthetic "reachable" evidence | `WitnessAuthorityViewEvidence` |

Transport success may be reported separately as transport reachability,
but transport reachability must never feed authorization.

#### Holder classification (with remaining)

Derived from `TermStatusPayload.current_holder` and `lease_remaining_ms`.
Client code must not invent lease expiry that Witness has not committed.

| Case | Classification | Authority-view |
|------|----------------|----------------|
| `holder = None` | `CompatibleNoHolder` | compatible |
| `holder = Self` and `remaining > 0` | `CompatibleSelfUnexpired` | compatible |
| `holder = Self` and `remaining = 0` | `ExpiredButUnprocessed` | **incompatible** |
| `holder = Foreign` and any remaining | `ConflictingHolder` | **incompatible** |
| `holder = Some(_)` and `remaining = 0` | `ExpiredButUnprocessed` | **incompatible** |

`CompatibleNoHolder` proves only: the Witness currently records no lease
holder for this term. It does not prove resource shutdown. All remaining
resource-safety guarantees come from later lease/resource contracts.

`CompatibleSelfUnexpired` is a quorum fact only. It is **not**
`RuntimeLeaseAuthority`, not `AttemptBoundLeaseAuthority`, and cannot
execute mutation.

#### Local communication-loss freshness

Stale `CommunicationLost` must not combine with fresh Witness evidence.

Rule (OPTION D — generation + monotonic age):

- Fresh local loss begins when the failure detector enters
  `CommunicationLost` at monotonic time `lost_at` (confirmation window
  satisfied).
- Freshness is measured only with local monotonic time:
  `now - lost_at <= LOCAL_LOSS_EVIDENCE_MAX_AGE` (design constant;
  default proposal 30s; implementation may bound it with the existing
  confirmation window family).
- Invalidated by: trusted heartbeat recovery to `Healthy`, local restart,
  peer session re-establishment that resets observation, term movement
  for the current evaluation, or age expiry.
- Evaluation must sample this bound inside the single authority
  observation transaction (no second peer poll / no double ownership).

#### No-fencing contract

- Stage 13.3 does not fence the old peer.
- Witness holder state does not prove resource shutdown.
- `safe_deadline` demotion is local and best-effort.
- Lease expiry is not resource fencing.
- Stage 13.3 only decides whether **lease acquisition may be attempted**.
- No Stage 13.3 evidence permits direct resource activation.

Duplicate serving remains a documented no-fencing risk if an old Active
fails to self-demote. That risk is accepted for a future **explicit
manual** promotion path under operator assumptions, and remains
unacceptable for automatic failover until a stronger resource-ownership
or external fencing contract exists.

#### Protocol v1

**Wire unchanged.** Semantic clarification only: GET_TERM does not
perform lease expiry. `Some(holder) + remaining = 0` is
expired-but-unprocessed and is **not** authority-view-compatible.

#### Non-goals (unchanged)

No CLI promotion, no automatic failover, no lease acquisition, no
resource mutation, no Authorized caching, no second Witness session or
outstanding slot, no async/re-entry.

#### Layering preserved

```
Ready != Eligible != Authorized != PromotionAttempt != LeaseAuthority != Promoted
```

Authorized is only permission to enter Stage 13.2 fresh lease acquisition.

## v1.0 追補: 追加された構成要素

| モジュール | 役割 |
|---|---|
| `witness_server` | `mikagami witness {init,run,rearm}`。accept loopと接続ごとのスレッド、既存のauthority実装（`witness_authority`/`witness_state`/`witness_scheduler`）を無変更で呼ぶ。判定ロジックを持たない |
| `bootstrap_admission` | Bootstrap Admissionの純関数（時計・I/Oなし）。`BootstrapClearance`は`decide`内の1か所でだけ生成され、BA用ARM+promoteでだけ消費される |
| `obligation_reconciliation` | 起動時整合（SOR）の判定とstore適用 |
| `auto_failover` | 自動トリガーの純粋な状態機械（時刻は注入）。昇格要求の生成のみ |
| `health_hysteresis` | healthの連続回数による安定状態（助言用。昇格の判断には使わない） |
| `command_service` | `service.manager = "command"`のadapter（`resource_executor`から`#[path]`で取り込む） |

Daemonの`tick_at`は、観測→peer進行（応答器のverdictを同一呼び出し内で計算）→遷移ログ→BA outcome回収→（Witness接続喪失の検査）→自動トリガーのpollの順に1回ずつ進む。自動トリガーは1ビットの要求を立てるだけで、観測ループの**同一の消費点**（手動SIGUSR1と同じ`promote`クロージャ）でのみ試行になる。
