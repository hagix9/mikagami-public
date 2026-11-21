# Persistence

> 開発者向けの設計・検証の記録です。開発の工程の識別子（段階や判断の番号）と、公開候補に含まれない内部の資料への参照を含みます。利用の手順は [`README.md`](../README.md) と [`configuration.md`](configuration.md) を参照してください。

NodeとWitnessの永続化は分離する。

## Node

Node stateが破損した場合は`Failed`とし、自動再生成しない。管理者の明示操作後に`RecoveryPending`へ入り、VIP、service、peer、Witness、term、leaseを再観測してreconcileする。

保存されたOperationPhaseやoperation_idだけから副作用を再実行したり、途中処理を再開したりしない。

### Stage 9 Node Mutation Persistence

Witnessのmutating request（`LEASE_REQUEST`、`LEASE_RENEW`、`LEASE_RELEASE`）用Node永続化は、Witness persistent v2とは別の専用format namespaceとする。Node mutation stateの`state_format_version`は`1`であり、Stage 9ではmigrationを実装しない。

概念上の`NodeMutationPersistentState`は次を保持する。

```text
state_format_version = 1
cluster_id
node_id
initialization_id
highest_started_mutation_generation
outstanding_mutation
```

`initialization_id`は明示的初期化時に生成するcanonical lowercase hyphenated UUIDv4であり、通常の再起動、term/lease変更、config reload、outstanding completionでは変更しない。これはlocal state identityであり、Protocol v1へ送信するfencing tokenではない。

`highest_started_mutation_generation`は「Nodeが新しいlogical mutating requestとしてdurably開始した最大generation」を意味する。last completed、next generation、Witness watermarkではない。新規mutationでは`checked_add(1)`したgenerationと完全な`outstanding_mutation`を同一candidateとして保存し、保存成功後にのみsend可能とする。generation 0は禁止し、`u64::MAX`は最後のlegal generation、到達後はwrap/resetせず新規allocateを拒否する。

`outstanding_mutation`は最大1件で、`request_id`、`mutation_generation`、kind、完全なsemantic payloadを保持する。payloadは、LEASE_REQUESTでは`observed_term`・`priority`・`requested_ttl`、LEASE_RENEWでは`term`・`lease_id`、LEASE_RELEASEでは`term`・`lease_id`・`reason`を保存する。`session_id`、transport sequence、HMAC、wire bytes、TCP state、retry timerは保存しない。

構造的不変条件は、outstandingが`None`ならgenerationは`0..=u64::MAX`、`Some`ならoutstanding generationが`highest_started_mutation_generation`と完全一致することである。不一致、部分状態、unknown field、未知version、cluster/node identity不一致、canonical UUIDv4でないidentityはfail closedとする。

通常runtimeでstate fileがmissingの場合、brand-new Nodeとはみなさず`InitializationRequired`/`RecoveryPending`相当として扱い、自動初期化・generation reset・Witness送信を行わない。新規作成は明示的な初期化操作だけが行い、既存valid/corrupt/unknown stateをoverwriteしない。同じnode_idをstate loss後にgeneration 0から再利用する場合は自動recoveryではなく、管理者によるreconcile、new node_id等の別手続きが必要である。

retryは同じ`request_id`、generation、kind、semantic payloadを使用する。current term、lease、priority、TTL、reason等で保存済みoutstandingを書き換えない。transport envelope、session、sequence、HMACだけは再構築してよい。

terminal completionは`request_id`、generation、kindの一致を要求する。`AcceptedSuccess`、`DeterministicReject`、`RetiredStale`だけがclear可能なdispositionであり、Retired/Staleは元のsuccessを証明しない。Conflict、GenerationGap、transport/timeout/NotReady/persistence等の不明・一時的結果はclearせず、outstandingを維持する。一致したcompletionは`highest_started_mutation_generation`を変更せず、outstandingを`None`にしたcandidateをatomic saveし、保存成功後にのみ完了とする。

Node stateの永続化は、candidate validation、unique temp file、restrictive permissions、write、file fsync、atomic rename、parent directory fsyncの順序で行う。atomic persistenceはtorn writeを防ぐが、外部からのvalidな古いsnapshotへのrollbackを一般には検出できない。疑わしいrestoreは管理者reconcileとし、generationを飛ばす自動修復は行わない。NodeMutationPersistentState、NodeMutationStore、explicit initialization、allocator、recovery、terminal completionのRust primitiveはStage 9で実装済みである。explicit init CLI、Witness transport/response integration、retry scheduler、RetiredStale reconcile、Node demotion、fencingは未実装である。

## Witness

Witnessは最低限、以下を永続化する。

```text
cluster_id
current_term
active_lease_id
holder_node_id
lease_ttl_ms
lease_deadline_monotonic_ms
lease_state
boot_id
```

新lease発行時の原則：

```text
term更新
→ lease情報更新
→ temporary file write
→ file fsync
→ atomic rename
→ parent directory fsync
→ LEASE_GRANT
```

termとlease情報がdurableになる前に`LEASE_GRANT`を返さない。lease更新も、必要なlease状態をdurableにしてから成功応答を返す。

`lease_deadline_monotonic_ms`は、同一OS boot内でのみ保存済みlease期限を復元するために使用する。Witnessのmonotonic clock期限は再起動をまたいで無条件に信用しない。OS rebootで保存済み`boot_id`と現在のboot_idが異なる場合、保存済みdeadlineを絶対に信用せず、旧leaseの期限を安全に判断できないため、Witnessは`NotReady`となる。

この状態では、

- 新leaseを発行しない
- termをリセットしない
- 管理者介入を要求する

書き込み途中の停止では、atomic rename前の旧ファイルまたはrename後の完全な新ファイルだけを採用する。ファイル破損、term復元不能、lease復元不能の場合もfail closedとする。

Witnessプロセス停止やOS再起動では可用性が低下し得る。これは安全性を優先した仕様であり、Witnessはfencingではない。

### F-01.1 persistent recovery transaction

### Recovery Transaction Contract v1.1

Post-remediation auditで確認されたR-01、R-02、R-03、R-06を閉じる実装契約を定義する。Recovery Metadata v1のオンディスク形式は変更しない。

#### Serialized safety domain

一つのcanonical pathについて、recovery inspection、canonical snapshot取得、canonical persistenceは同じprocess-globalなpath transaction lockで直列化する。`NodeMutationStore`や`WitnessStateStore`の各handleが独自lockを持つのではなく、同一path identityから同じlock registry entryを取得する。

通常のread transactionは次の順序とする。

```text
path transaction lock取得
→ process-local uncertainty確認
→ recovery marker inspection
→ canonical file bytesを完全にread
→ lock解放
→ コピー済みimmutable bytesをparse／semantic validation
→ snapshot返却
```

parseとsemantic validationがimmutableなbytesだけを参照する場合はlock解放後に実行できる。marker、canonical file、boot_id、別ファイル、process-local registryを参照する検証はlock解放後に行わない。Witnessのboot_idやclockの取得など、snapshot以外のauthority判定はread transaction完了後に別の明示的境界として扱う。

通常のwrite transactionは同じlockを保持したまま、次の全区間を実行する。

```text
path transaction lock取得
→ process-local uncertainty確認
→ recovery marker inspection
→ durable PREPARE
→ candidate write／fsync
→ canonical namespace mutation
→ canonical parent directory fsync
→ recovery marker cleanup／directory fsync
→ lock解放
```

network I/O、scheduler wait、service/VIP操作はRecovery transaction lockの内側で実行しない。Node/Witnessの上位lockは残せるが、同じcanonical pathの安全性はRecovery path lockが単独で保護する。

#### Path lock identity and ordering

Recovery Transaction v1.2では、process-globalな`PathIdentity → Arc<Mutex<()>>`に加えて、各Storeが一度だけ構築する`ResolvedStorePath`を導入済みである。これはcanonical I/O path、resolved parent directory、PathIdentity、official recovery marker、candidate／marker temporaryの配置先、parent directory fsync対象を同じ解決結果から保持する。lock pathとI/O pathを別々に計算しない。

path resolutionは文字列の`.`／`..`除去を先に行わず、filesystemのcomponent traversalを行う。絶対化した起点からcomponentを順に処理し、parent componentはその時点のresolved directory stackへ適用する。途中componentのsymlinkは`read_link`で展開し、relative targetは現在の親directoryから、absolute targetはrootから再開する。これにより`/srv/base/link -> /srv/real/sub`に対する`/srv/base/link/../state`は`/srv/real/state`として解決される。symlink展開には上限を設け、loopや解決不能componentはfail closedとする。既存のparent-directory symlinkはこの方式で引き続きサポートする。

final componentは通常のsymlink追跡対象にせず、`symlink_metadata`で検査する。regular fileは受理し、NotFoundはfinal componentが存在しない場合だけexpected absenceとして受理する。final componentのsymlink、directory、non-regular object、parentのpermission errorまたはnon-directoryは拒否する。final componentが初期化後にsymlinkへ置き換わった場合も、transaction開始時の同じ検査で拒否する。relative／absolute、`.`／`..`、nested parent symlink、同じcanonical objectへ到達する複数aliasは、同じResolvedStorePath、marker、transaction registry entry、uncertaintyを共有する。

ResolvedStorePathはStore construction時にcaptureし、single owning processと固定されたparent namespaceを前提に、その後の全transactionで再利用する。external namespace mutation、複数process owner、NFS／SMB等は引き続き対象外である。construction後にparent symlinkを差し替える運用はサポートしない。final componentのsymlink検査だけは各read/write境界でも行い、禁止された置換を受理しない。

registry entryはprocess lifetime中に保持してよい。stale entryの削除はlockの寿命を壊さない所有方式が必要なため、MVPでは安全性を優先してbounded cleanupを要求しない。lock poisonは当該pathのread／writeをfail closedにする。

lock順序は、同一pathについて常に`Recovery path lock → canonical filesystem operation`とする。Node mutation lock、Witness authority mutation lock、scheduler state lockは、Recovery path lockを保持したまま取得しない。network I/Oはすべての永続化lockの外で行う。この順序を守ることで、Node lock → Recovery lockとRecovery lock → Node lockの循環を作らない。

#### Uncertainty and multiple handles

uncertaintyはStore objectではなくprocess-globalなpath identityへ紐付く。Handle Aがpathをuncertainにした場合、同じidentityのHandle Bも直ちに次を返す。

```text
normal read             → RecoveryRequired / NotReady
normal write            → RecoveryRequired
normal begin            → prohibited
normal completion       → prohibited
Witness save            → prohibited
normal migration        → prohibited
scheduler mutation     → prohibited
authoritative GET_TERM  → prohibited
```

明示的administrator recoveryだけがuncertain状態を解消できる。通常のsave、load、retry、再migrationはuncertaintyをclearしない。

readerはpath lock取得後にactive markerを見つけた場合、writerの処理中ならwriter終了まで待ち、終了後に再確認する。markerが残っていればRecoveryRequired、writerがpre-canonical failureを確実にcleanupしていればOLDをread、clean commit後にcleanup済みならNEWをreadできる。readerがwriter transactionの途中のmarkerやcanonical imageを観測することは許可しない。

#### PREPARE no-overwrite and temporary names

`<canonical>.recovery`のPREPARE installは、通常の`rename`を使わない。同じfilesystem上で、fsync済みtemporary markerを`hard_link(temp, marker)`でno-replace installする。destinationが存在する場合はlinkが失敗し、既存markerのbytesを変更しない。destination存在を検出した新transactionは既存markerを削除せず、canonical mutationへ進まず、RecoveryRequiredまたは同等のfail-closed結果を返す。

PREPARE marker自体は別のrecovery transactionを必要としない。

```text
temporary marker write
→ file fsync
→ hard_link no-replace install
→ parent directory fsync
```

hard-link成功後、source temporary pathnameは安全にunlinkする。marker inodeはhard-linkで残っているため、source aliasのunlinkはauthority markerを削除しない。source aliasのunlink／そのdirectory fsyncが失敗した場合、marker installとparent fsyncが既に確認済みならcanonical authorityは不確定化せず、再起動時に安全に無視できる一時garbageとして扱う。ただし、marker本体のunlink失敗とは区別する。

marker temporaryとcanonical candidate temporaryの名前は、固定counterだけに依存しない。既存のCSPRNG UUID生成または同等のprocess-unique random transaction componentを含め、同じdirectoryに`create_new`で作成する。stale temporaryはcanonicalやrecovery markerとして解釈せず、authority recoveryの根拠にしない。未知のstale temporaryを通常transactionが削除する必要はなく、cleanup失敗でnormal transactionを永続的に阻害しない。candidate temporaryもhard-link sourceまたはcanonical rename sourceとしての役割が終われば安全にunlinkする。

#### Snapshot provenance, stale candidate, and restart

readが返すsnapshotは、path lock内で完全にcopyされたcanonical bytesと、その時点で確認したrecovery状態から構成する。parse後にfilesystemを再参照しない。

write callerが古いsnapshotからcandidateを作成する場合、candidateはそのsnapshotとruntime-onlyの`ExpectedOldToken`を一体として保持する。tokenはcanonical bytesのSHA-256 identity、または初期化時だけのexpected absenceを表し、永続化せず、Protocolへ送らず、authority・durability proofとして扱わない。同じpath lock内でtokenと現在canonical bytesを比較し、不一致ならPREPARE前にcandidateをinstallせずfail closedする。tokenを「save時点のcurrent bytes」から再生成してはならず、上位Node／Witness lockに依存してこの比較を省略しない。

`persist_current`は通常のstale-sensitive candidate updateから除外する。残す場合も、expected absenceを検証する初期化、または明示的に証明された内部special pathだけに限定し、既存canonicalを現在値で暗黙に承認するpublic mutation APIとしては公開しない。通常のNode／Witness loadは`LoadedSnapshot { parsed_state, ExpectedOldToken }`を返し、`save`／`commit_candidate`はこのprovenanceを要求する。任意candidateとcurrent stateを組み合わせるだけの経路は削除またはrestrictedとする。

explicit legacy migrationも、検査したlegacy bytesからExpectedOldTokenを作成し、そのtokenを伴うcandidateとして保存する。別handleが先にS1をcommitした場合、S0由来のmigrationはPREPARE前に拒否され、S1のauthority、journal、watermarkを上書きしない。initializationは別のexpected absence tokenを使用し、canonicalが存在すればPREPARE前に拒否する。読み取りerrorをabsentへ変換しない。

process-local uncertaintyはrestartで消えるため、restart後の安全性はmarkerとcanonical transaction orderに依存する。canonical namespace mutationまたはcanonical parent fsyncが不確定ならdurable PREPARE markerが残り、markerがある限りNotReady／RecoveryRequiredとする。canonical parent fsyncがConfirmedCommittedになった後にmarker cleanupを開始するため、cleanup unlink後のdirectory fsyncが不確定でmarkerが消えても、canonical NEWのcommit自体は既に確認済みであり、通常restartを許可できる。これはpre-canonical failureには適用しない。

OLD／NEW／NEITHERのfingerprint分類はrecovery inspectionのidentity補助だけに使う。NEW一致、parse成功、再read成功、再fsync成功だけでCommitOutcomeUnknownをConfirmedCommittedへ変換しない。

#### Caller semantics

Node beginは、candidate generation／request_idを作成してdurable `ConfirmedCommitted`を得た後だけsendable mutationを返す。PreCommitFailureはsendせずOLDを通常利用できる。CommitOutcomeUnknownまたはCleanupOutcomeUnknownはsendせず、path uncertainとして次generationとnormal retryを禁止する。

Node completionは、exact outstandingをclearするcandidateのdurable `ConfirmedCommitted`後だけterminal completionを返す。canonical bytesが既に`outstanding = None`になっていても、completion transactionがambiguousなら完了扱いにしない。N+1 generationも許可しない。

Witnessのgrant、deterministic reject、renew、release、expiryは、authority、journal、watermarkを含む一つのcandidate snapshotをRecovery transactionでconfirmed durableにしてからresponseを送る。GET_TERMはsafe snapshotからprojectionを作り、Recovery lock解放後にresponseを構築・送信する。recovery中のGET_TERMはauthoritative Readyを返さない。schedulerはsafe snapshotを取得してlockを解放し、mutation直前に通常write transactionを再取得する。古いcached snapshotだけでauthority mutationを実行しない。

explicit legacy migrationはnormal loadから分離され、同じpath transaction lockとuncertainty gateを通る。通常loadはbytesを変更せずMigrationRequiredを返す。

#### Crash matrix revision

| point | lock／uncertainty | marker／canonical | same-process normal read／write | restart | admin recovery |
|---|---|---|---|---|---|
| P0 PREPARE前 | lock未取得、uncertainなし | marker absent、OLD | read/write可 | validation後可 | 不要 |
| P1 marker temp中 | writerがlock保持 | marker absentまたはtempのみ、OLD | readerは待機、他writerは待機 | crash後markerの有無を検査 | markerがあれば必要 |
| P2 marker install／dir fsync前 | lock保持 | durable marker不確定、OLD | 待機中readerはmarker再検査 | markerあればRecoveryRequired | 必要 |
| P3 PREPARE confirmed | lock保持 | durable marker、OLD | 通常read/write不可 | RecoveryRequired | 必要 |
| P4 candidate中 | lock保持 | durable marker、OLD、candidateは非authoritative | readerは待機 | markerありならRecoveryRequired | 必要 |
| P5 canonical install前失敗 | lock保持 | OLD、marker cleanup確認済みならabsent | PreCommitFailure後に再開可 | OLDを通常利用可 | 不要 |
| P6 canonical mutation後 | lock保持、uncertain on ambiguity | NEW／旧可視、durable marker | readerは待機、write不可 | markerありならRecoveryRequired | 必要 |
| P7 canonical parent fsync後 | lock保持 | NEW、durable marker | cleanup完了まで通常不可 | markerがあればrecovery | marker cleanupが必要 |
| P8 marker cleanup中 | lock保持 | NEW、marker durable／unlink中 | readerは待機 | markerありならrecovery | 必要 |
| P9 unlink後／cleanup dir fsync前 | lock保持、uncertainなら設定 | NEW、marker visible／absent | uncertainならread/write不可 | marker absentならNEWを通常利用可 | 不要、commit confirmed |
| P10 cleanup dir fsync後 | lock解放、uncertainなし | NEW、marker absent | read/write可 | validation後可 | 不要 |

P5はcanonical namespaceが変更されていないこと、marker unlinkとparent fsyncが確認済みであることを同時に要求する。P9はcanonical parent fsyncがP8より前に成功しているため、markerが消えてもNEWのdurability ambiguityを作らない。

F-01.2で、このRecovery Metadata v1 transaction boundaryをNodeMutationStoreとWitnessStateStoreの実際の初期化・保存・mutation callerへ統合し、不確定結果のprocess-local poisoningと決定的fault-injection test seamを実装した。Recovery Transaction v1.2では、これにResolvedStorePathとcandidate provenanceを追加済みである。既存のcanonical state formatと本節の安全性契約は変更しない。

Node Persistent v1、Witness Persistent v2、journal、watermarkの形式は変更しない。canonical state fileとは別に、同じディレクトリ・filesystem上の`<state-path>.recovery`をRecovery Metadata v1として使用する。これはauthorityやcompletionの証明ではなく、存在する限り通常復旧を禁止するためのwrite-ahead recovery evidenceである。

Recovery Metadata v1は、`recovery_format_version`、store kind、cluster identity、nodeまたはWitness identity、transaction_id（CSPRNG UUIDv4）、operation class、canonical path identity、expected OLD SHA-256、candidate NEW SHA-256を保持する。fingerprintは可視byte列の識別だけに使用し、durabilityやauthorityの証明には使用しない。metadata自体はstrict validation、identity validation、regular-file／非symlink検査、0600相当の権限検査を受ける。unknown version、破損、identity/path不一致はfail closedとする。

通常保存は、OLDを検証し、recovery metadataをtemporary fileへwrite/fsyncし、no-overwriteでinstallし、parent directoryをfsyncしてPREPAREをConfirmedCommittedにしてから、candidateをwrite/fsyncし、canonicalをrenameまたはhard-linkし、canonical parent directoryをfsyncする順序とする。PREPARE確認前のcanonical mutationは禁止する。canonical commit確認後にだけrecovery metadataをunlinkし、parent directoryをfsyncする。

PREPARE install後のfsyncが不確定でもcanonicalは未変更なのでauthorityは変わらない。candidate fsync失敗、またはcanonical installの明示的な未変更失敗は、marker cleanupとそのparent directory fsyncまで確認できた場合だけ`PreCommitFailure`として旧stateの通常retryを許可する。cleanupが失敗・不確定なら`CommitOutcomeUnknown`としてstoreをuncertainにする。canonical mutation後のparent fsync失敗は`CommitOutcomeUnknown`であり、同一processのload、save、begin、complete、authority mutation、expiry、GET_TERM projectionを通常実行しない。success、Duplicate、次generation、次leaseを生成してはならない。

canonical commit確認後のmarker cleanupが不確定になった場合、markerが残れば再起動後は保守的にrecoveryへ入る。markerが消えてもcanonical commitは既に確認済みであるため安全であり、cleanup ambiguityはfalse-positive recoveryだけを生む。可視file、parse成功、fingerprint一致、再fsync成功だけでCommitOutcomeUnknownを解消してはならない。

process restart時にmarkerが存在する場合、canonicalがparseできてもReadyにしない。OLD／NEW／NEITHERのfingerprint分類は補助情報であり、NEW一致はcommit proofではない。完全なOLD／NEW snapshotはmetadataへ複製せず、NEITHER、必要なrollback bytesの欠落、identity不一致、boot_id変更、metadata破損は管理者recoveryを要求する。管理者recoveryは選択したbaselineを新しいtransactionとしてconfirmed durableに保存してからmarkerをcleanupする。

Node begin ambiguityでは送信せず、新generationを開始しない。completion ambiguityでは次generationを許可せず、canonicalのoutstanding=Noneだけを根拠にclear済みと扱わない。Witnessのgrant、deterministic reject、renew、release、expiryはいずれも不確定時にsuccess／PolicyReject／Duplicateを返さず、NotReadyとしてauthority mutationとschedulerを停止する。authority、journal、watermarkは一つのOLD／NEW／UNKNOWN imageとして扱う。

通常起動は、recovery markerが確実に存在せず、canonical validation、identity、boot_id、path安全性を満たす場合だけ許可する。MVPは一つのstate directoryを一つのMikagami processだけが所有・変更することを前提とし、外部writerと複数process ownerはunsupportedである。同一process内の別handleもmarkerを確認し、marker存在時は通常操作を拒否する。

対象filesystemは、canonical state、recovery metadata、temporary fileが同じ信頼できるlocal Linux filesystemにある場合に限る。NFS、SMB/CIFS、分散filesystem、durabilityを保証しないstorage、外部writerは対象外とする。file fsyncとdirectory fsyncは別のdurability barrierであり、namespace visibilityはその代替ではない。OS／power crash後のmonotonic deadlineは既存boot_id規則に従う。

### F-03 explicit legacy Witness migration

Witnessのversionless legacy stateは、通常の`load()`では自動移行しない。`load()`はcanonical bytesを変更せず、`MigrationRequired`としてNotReadyを返すため、GET_TERM、authority mutation、schedulerを含む通常経路は明示的移行なしにlegacy stateを利用しない。missing、破損、current v2、recovery markerはそれぞれ別の結果として扱う。

移行は管理者が明示的に呼び出す`migrate_legacy_explicitly()`だけで行う。strictに認識でき、configured clusterとcurrent `boot_id`が一致するversionless legacy stateに限り、legacyのterm・lease・deadlineを保持し、journalとgeneration watermarkを空で初期化する。保存はF-01.1 transactionを通し、pre-canonical failure後のmarker cleanupが失敗・不確定ならRecoveryRequiredとしてfail closedにする。current v2、recovery marker存在、boot_id不一致は移行を拒否する。

### Stage 3.9 authority policy clarification

`LEASE_REQUEST`のNewEligible authority policyは、`observed_term == current_term`、`requested_ttl == 10_000ms`、`LeaseState::None`、checkedなterm increment、monotonic deadline加算、CSPRNGによる独立UUIDv4 lease_id生成を要求する。`Active`、stale/future observed term、TTL不一致、term exhaustionはdurableな`LeaseReject`としてjournalとwatermarkをauthority stateと同じatomic saveでcommitする。`Unknown`、NotReady、clock/CSPRNG/persistence failureはpre-commit fail closedであり、generationをconsumeしない。

Duplicate grantは、保存済みgrantとcurrent Active authorityのterm・lease_id・holder・lease TTLが一致し、current durable authorityにmonotonic deadlineが存在する場合だけ許可する。stored grantのabsolute deadlineとの比較は要求せず、remainingをcurrent authorityの同一boot monotonic deadlineから再計算する。identity不一致またはremaining zeroはfail closedとする。lease expiry processingおよびLEASE_RENEW/LEASE_RELEASE authorityは未実装である。

### Stage 4.9 LEASE_RENEW policy

Stage 5のLEASE_RENEWはcurrent Active leaseのterm・lease_id・holder本人・TTL 10,000ms・deadlineを確認し、同一bootのmonotonic `now < deadline`の場合だけ許可候補とする。成功時はterm・lease identityを維持し、`now.checked_add(10_000ms)`を新deadlineとして、authority state・`LeaseRenewed` journal result・watermarkを一つのcandidateとしてatomic saveする。`None`、期限切れ、identity/TTL不一致はdeterministic `LeaseReject`としてcommitし、Unknown、metadata欠落、clock/overflow/persistence failure等はpre-commit fail closedとする。

Duplicate `LeaseRenewed`は期限を延長せず、current durable deadlineからremainingを再計算する。後続renewalによる新しいdeadlineを許可し、stored resultのabsolute deadlineとは比較しない。remaining zeroまたはidentity不一致はfail closedとする。LEASE_RENEW authorityは実装済みであり、LEASE_RELEASE authority、expiry processingは未実装である。

### Stage 5.9 LEASE_RELEASE policy

LEASE_RELEASEのNewEligible requestは、ReadyなWitnessのcurrent Active authorityに対してterm・lease_id・holderが一致する場合だけ評価する。deadlineの正負や期限超過はrelease可否に影響せず、期限切れのActiveも一致すれば解放できる。Noneは過去のreleaseを証明しないためdeterministic reject、Unknownやmetadata不整合はpre-commit fail closedとする。

成功時はtermを維持し、lease state、active lease_id、holder、TTL、deadlineをNoneにしたcandidateへ、LeaseReleased result、journal record、requester watermarkを含めて一度のatomic durable saveを行う。LeaseReleased responseはpost-release authority（current term、lease_id None）を表す。response送信失敗でもcommitはrollbackしない。Duplicate成功はjournal resultを再生し、current stateをNoneにする必要はなく、後続の別leaseを変更しない（ABAを含む）。Duplicate rejectも再評価せず再生する。Retired/Stale、Conflict、GenerationGapはauthority・journal・watermarkを変更しない。

このreleaseはservice停止、VIP解放、fencing、旧Active停止を表さない。Nodeのlocal demotionはreleaseの応答やqueueを待たない。Stage 6でLEASE_RELEASE authorityを実装済みとするが、Node integrationとexpiry processingは未実装である。

### Stage 6.9 Witness lease expiry processing policy

expiryはWitness-local authority maintenanceであり、Node-originated requestではない。新しいrequest_id、mutation_generation、journal record、generation watermark更新を行わず、既存persistent v2 schemaを変更しない。ReadyなWitnessの整合したActive authorityについて、same-boot monotonic clockの`now >= lease_deadline_monotonic_ms`だけをexpiry eligibilityとする。`now < deadline`はno-op、境界値`now == deadline`と超過はexpiry候補である。Noneはno-op、Unknown、NotReady、metadata不整合、clock failureはfail closedとする。

expiry成功candidateはcurrent_termを維持し、lease stateをNone、active_lease_id・holder_node_id・lease_ttl_ms・lease_deadline_monotonic_msをNoneにする。既存journal、generation watermarks、retirement metadataを変更せず、authority state全体を既存atomic durable saveで一度だけcommitする。保存失敗時は旧Activeが authoritativeであり、memoryだけをNoneにしてgrantを許可してはならない。crash recoveryは旧complete Activeまたは新complete Noneだけを採用する。

expiryとLEASE_RENEW/LEASE_RELEASEは同一authority snapshotに対して直列化し、stale candidateによるlost updateを防ぐ。expiryはLEASE_REQUESTへ暗黙に組み込まず、expiry commit後のNoneだけが次のgrantを許可する。expiry前のGET_TERMはexpired Activeとremaining 0を返し、expiry後は同じtermのNone authorityを返す。expiryはfencingでも実リソース停止の証明でもない。

Stage 7でWitness lease expiry maintenance primitiveを実装済みとし、Stage 8でscheduler/runtime integrationを実装済みとする。persistent state format v2はFROZENのまま維持する。

## Stage 2.1 durable idempotency journal

Mutating Witness requestのdurable idempotency情報は、authority stateと同じpersistent state内に保持する。`state_format_version = 2`では、bounded journal、request kind、requester、semantic fingerprint、committed semantic result、generation watermark、retirement metadataを扱う。journal recordとauthority stateは別々に保存せず、1つのcandidate stateを既存のatomic durable saveでcommitする。Stage 2.1のjournal machineryは実装済みであり、Stage 4ではLEASE_REQUEST authorityへ接続する。

legacy Stage 2/3 stateは、Stage 4 authorityが未実装だったことを検証したこの移行点に限り、明示的なv2 migrationでempty journalとして扱える。v2のjournal欠落、unknown future version、downgrade、journal corruptionはfail closedとし、自動的にjournalを捨てたり再生成したりしない。

### Stage 2.0.2 generation watermark

bounded journal eviction後のretirement proofとして、Witnessはrequester nodeごとの`highest_committed_mutation_generation`をdurableに保持する。`mutation_generation`はmutating Witness requestのwire payloadに置くu64値で、新しいlogical requestで増加し、retryでは再利用する。authority state、journal、generation watermark、retirement metadataは同一のcandidate stateとしてatomic durable saveする。

active journal recordの完全一致はDuplicateとして結果を再利用し、journal missでgenerationがwatermark以下ならRetired/Staleとして拒否する。`watermark + 1`と一致するものだけをNewEligible候補とし、それを超えるgenerationはGenerationGapとしてfail closedにする。safe retirement proofなしのevictionは行わず、capacity fullではfail closedとする。既存Stage 2/3 stateの明示的migrationでは、Stage 4 authority未実装のhistorical invariantを検証したうえでwatermarkをrequesterごとに0として初期化する。counter rollback、state喪失、unknown version、破損はfail closedとする。

### Stage 2.0.3 Node mutation state

generation allocatorはrequester Nodeが所有する。Node persistenceはWitnessの`state_format_version`とは別のversion namespaceとし、generation counter、outstanding mutationのrequest_id・generation・kind・完全なsemantic payload（または再構築可能な情報）を同一のdurable candidateとしてatomic saveする。保存成功前のsendは禁止する。Node専用format/versionとbootstrap・state lossの扱いはStage 9.0で固定する。

requesterごとにone-outstandingとし、restart後や送信・応答不明時は同一requestをretryする。Witnessのdurable terminal decision（successまたはdeterministic reject）はgenerationをconsumeし、commit前transient failureはconsumeしない。Node state loss、counter rollback、同じnode_idの再利用ではwatermarkから自動再生成せず、Failed/RecoveryPendingと管理者reconcileへ移行する。

generation watermarkはlease lifecycle、term、process restart、OS reboot、journal emptyを理由にresetしない。legacy Witness migrationはStage 4 authority未実装のhistorical invariantを検証した場合のみ、known requesterのwatermark 0を許可する。Witnessの有効な古いsnapshotへのrollbackは、既存のboot_idおよびatomic write検証だけでは一般に検出できない。

### F-01.1 outcomes and crash matrix

保存結果は概念上、`PreCommitFailure`、`ConfirmedCommitted`、`CommitOutcomeUnknown`に分ける。PreCommitFailureはcanonical namespace未変更を確認できる場合だけであり、旧stateを継続利用できる。ConfirmedCommittedだけが通常のsuccess、completion、次generation、authority responseを許可する。CommitOutcomeUnknownはnamespace mutation後に必要なbarrierの結果が不明な状態であり、storeをuncertainにして通常操作を禁止する。

| point | canonical | recovery record | candidate | restart classification | automatic action / authority |
|---|---|---|---|---|---|
| P0 before PREPARE | OLD／未初期化 | absent | absent | normal validation／initialization required | 既存条件を満たす場合のみ通常操作 |
| P1 PREPARE write中 | OLD | absentまたは不完全 | absent | markerがなければOLD、あればrecovery | canonical authority不可、markerは管理者recovery |
| P2 PREPARE fsync後、dir fsync前 | OLD | visibleまたはabsent | absent | markerがあればrecovery、なければOLD | canonical未変更、通常操作は再起動後判定に従う |
| P3 PREPARE confirmed | OLD | durable PREPARE | absentまたは作成前 | recovery transaction active | canonical mutation以外のauthority不可 |
| P4 candidate write中 | OLD | durable PREPARE | absent／partial | crash時はmarkerがあればrecovery | partial candidateを採用しない。明示的失敗後はcleanup確認済みPreCommitFailure |
| P5 candidate fsync後 | OLD | durable PREPARE | complete | crash時はmarkerがあればrecovery | canonical installの明示的未変更失敗はcleanup確認済みPreCommitFailure |
| P6 canonical rename／link後 | NEW visibleまたは旧 | durable PREPARE | absent／残存 | 必ずrecovery | Nodeはsend／次generation不可、WitnessはNotReady |
| P7 canonical parent fsync後 | NEW | durable PREPARE | absent／残存 | recovery（cleanup前） | canonical commitのみconfirmed、通常操作はcleanup後 |
| P8 marker cleanup中 | NEW | durable／unlink途中 | absent／残存 | markerがあればrecovery | NEWを推測して通常化しない |
| P9 unlink後、cleanup dir fsync前 | NEW | visibleまたはabsent | absent | markerが残ればrecovery、消えていれば通常validation | false-positive recoveryのみ許可 |
| P10 cleanup dir fsync後 | NEW | absent | absent | normal validation | 通常操作可 |

P1〜P3のmarker不確定でmarkerが消える場合、canonical mutationはまだ行われていないためauthority transitionは発生しない。P6以降はPREPAREが先にdurableなので、markerが残る限り再起動はrecoveryへ入る。P7のconfirmed commit後にP9でmarkerが消えることは安全であり、P6〜P7でmarkerが消えることは許可しない。process crash、OS reboot、power/storage crashは同じ分類表を使うが、OS rebootではboot_id変更を検査し、旧monotonic deadlineをauthorityに使用しない。

安全性の根拠は次のとおりである。

- A：PREPARE confirmed前のcanonical mutationを禁止するため、durable recovery evidenceなしのstate transitionは起きない。
- B：canonical mutationの前にPREPAREをdurableにするため、P6以降の再起動はmarkerに遭遇し、正常Readyへ黙って進まない。
- C：marker cleanupはcanonical commit確認後だけなので、cleanup ambiguityはmarkerを残すfalse-positiveだけを作る。
- D：Node beginはConfirmedCommitted後だけsendable resultを返す。
- E：Node completion ambiguityはstoreをuncertainにし、N+1を禁止する。
- F：Witnessのgrant／renew／release／expiry ambiguityはNotReadyとしてauthority successを禁止する。
- G：authority、journal、watermarkは一つのcanonical imageとして扱い、unconfirmed journalからDuplicateを再構築しない。
- H：PREPARE install ambiguityではcanonical mutationを行わないため、marker自体のmarkerは不要である。

Recoveryは通常`load()`へ暗黙に組み込まず、将来の明示的inspect／recover境界で行う。active marker、破損metadata、OLD／NEWいずれにも一致しないcanonical、必要なbaseline bytesの欠落、identity不一致、boot_id変更、storage errorは管理者判断を要求する。管理者の承認だけではauthorityにならず、選択したbaselineの新規confirmed durable saveが必要である。

### Stage 11 Node lease authority persistence boundary

Stage 11で扱う`NodeLeaseAuthority`の`term`、`lease_id`、`holder_node_id`、`local_safe_deadline`、`last_validated_at`はruntime-onlyである。monotonic deadlineをNode Persistent v1へ追加しない。Node restart後は旧leaseをusableと仮定せず、durable outstandingのexact retryまたはGET_TERM/reconcileを経てauthorityを再確立する。

LeaseRequest、LeaseRenew、LeaseReleaseのlogical identityは既存Node Persistent v1のrequest_id、mutation_generation、kind、semantic payload、outstandingを再利用する。AcceptedSuccess、PolicyReject、RetiredStaleだけが既存completion境界でoutstandingをclearできる。Conflict、GenerationGap、TemporarilyUnavailable、transport/auth/correlation uncertaintyでは同じmutationを保持し、N+1を作らない。lease authorityのruntime usabilityとmutationのdurable completionは別の結果である。

Stage 11はRecovery Metadata v1のmarker順序、Recovery Transaction v1.2のuncertainty gate、Witness Persistent v2のterm/lease/journal/watermark atomicityを変更しない。canonical commitがunknown、Node stateがRecoveryPending、WitnessがNotReadyの場合、fresh LeaseRequestで通常操作へ戻ることはできない。resource cleanupはLeaseReleaseのdurable responseやWitnessへの到達性に依存しない。

### Stage 11 recovery reconciliation table

| persisted/outstanding | observed local resources | Witness result | required action | RecoveryPending exit | promotion |
|---|---|---|---|---|---|
| none | VIP absent, service stopped | Ready or reconcileable | validate state, peer, Recovery, authority | Standby可 | Candidate後にgate |
| none | VIP presentまたはservice running | any | local stop/confirm、VIP release/confirm | cleanup確認後のみStandby | cleanup前は禁止 |
| none | VIPとserviceの両方が残る | any | service cleanup then VIP cleanup | zero-resource確認後のみ | cleanup前は禁止 |
| any LeaseRequest/Renew | resource不明を含む | unreachable/NotReady | exact mutationを保持しつつlocal cleanup、authority再取得不可 | observation/reconcile完了後のみ | 不可 |
| LeaseRelease | resources absent | success | completionをdurableに確定 | Standby可。ただし新規promotionは新gate後 | release履歴だけでは不可 |
| LeaseRelease | resources absent | reject/RetiredStale | historical successを推測せずreconcile | confirmed local safe stateとmutation handling後 | unresolvedなら不可 |
| LeaseRelease | resources absent | Conflict/Gap/temporary/transport | outstanding保持、N+1禁止 | reconcileまたは明示的terminal処理後 | 不可 |
| any | observation unknown | any | fail closed、local cleanupを可能な範囲で実行 | unknown解消まで不可 | 不可 |

RecoveryPendingからStandbyへ出る条件は、VIP不在、service停止確認、必要なpeer/Witness/term/lease観測、Recovery uncertaintyなし、persisted Node state valid、outstandingの扱いが安全に確定していることである。validated grant、GET_TERM success、outstanding retry successの単独成功はRecoveryReadyではない。RecoveryPendingのcleanupはWitness authorityや接続性を要求せず、resource-owning QuorumUnknownにも同じlocal cleanup境界を適用する。

## v1.0 追補

- **起動時整合（SOR）**: Node stateに解放義務Oが残ったまま起動したデーモンは、loopに入る前にWitnessへ問い合わせ、安全が示せる場合に限りOを原子的に消してStandbyに戻る（`NodeMutationStore::clear_superseded_obligation`、単一candidateの置換）。永続形式は変えない。未解決のM（別種のWitness変更）が残る場合や、Witnessのtermが自分の記録より古い場合は、`recovery gate blocked startup`と原因を出して起動しない。
- **Witnessの再起動**: 「rebootのたびにNotReady」ではなくなった。boot idが変わっていても、`on_reboot = "rearm"`（既定）なら1回の原子的commitでActiveなleaseの期限を「現在＋TTL」に再武装する（term・holder・journal・watermarkは変えない）。`refuse`、または状態ファイルが`rearm_max_downtime_sec`（既定3600秒）より古い場合は、運用者が`mikagami witness rearm`を実行するまでNotReadyを保つ。状態が**バックアップから復元された**ことは検出できない（termが巻き戻る）。
- 実行時の追加状態（Bootstrap Admissionのsession、自動切替の予算、peerのActive観測回数、healthの連続回数）はすべてメモリ内のみで、永続化しない。再起動で初期化される。

## v0.7 追補（正本は`MIKAGAMI_V07_CONTRACT_AMENDMENT.md`）

- **Witnessのjournal（C-J）**：容量は全requesterで64件。watermark以下の最も古い記録から消す。記録が残る間のexactなLEASE_RELEASEの再送はDuplicate、消えた後はRetiredStale。nodeは記録が残っているかを推測せず、時間を判定の入力にしない。容量は安全のparameterではない（`MIKAGAMI_V07_CONTRACT_AMENDMENT.md` §9 の T-01）。
- **Witnessの永続性の前提（C-W1）**：termは減らない、(term, lease id)は高々1回発行、失効・解放・置換がcommitされたleaseは再びActiveにならない、journalとwatermarkは古い写しに置き換わらない。実装はbackupやsnapshotからの復元を検出しない（上の「v1.0 追補」のとおり）。
- **P-fs（OS、filesystem、diskの耐久性）の受け入れの範囲（Q-W3、2026-11-18 Owner裁定）**：
  - P-fs-1〜P-fs-3（fileのfsync、directoryのfsync、renameの原子性）は、試験した条件の下で、guestのcrashに対して確かめた前提として受け入れ、この条件を運用の前提とする：GCEのimage `rocky-linux-10-arm64-v20261110`、boot disk `hyperdisk-balanced`、rootのfilesystemはXFS、mountのoptionはimageの既定（記録なし）、stateのdirectoryはrootのfilesystemの上（推定。未確認）。
  - **これと異なるimage、filesystem、mountのoption（barrierを無効にするoptionを含む）では、P-fs-1〜P-fs-3は受け入れの対象外である。** 物理的な電源断、稀な並べ替え、他のkernelは確かめていない。
  - P-fs-4（仮想のdiskがflush / FUAの完了の後に内容を失わない）は、GCEのplatformの保証に依る前提として受け入れる。根拠とするproviderの公開の記述は未確認である。
  - ENOSPCとEIO（F6-E）は試験しておらず、残余のリスクRR-32-6とする。PF-4（応答したtermがcrashの後もWitnessに残る）とPF-7（journalの窓の外のfail closed）は、GCEの証拠が無い。
