# Protocol

> 開発者向けの設計・検証の記録です。開発の工程の識別子（段階や判断の番号）と、公開候補に含まれない内部の資料への参照を含みます。利用の手順は [`README.md`](../README.md) と [`configuration.md`](configuration.md) を参照してください。

MVPのNode間およびNode-Witness間プロトコルは、認証済みの単純なrequest/response通信とする。protocol versionは完全一致のみ許可し、不一致時は接続を拒否する。

## Identifier roles

- `term`：Witnessが管理するActive権の世代。WitnessありではWitnessだけが増加させる。availabilityではglobal termではなく`local_epoch`
- `lease_id`：個々のleaseの識別子
- `session_id`：Mikagamiプロセス起動時に一度生成する暗号学的ランダムID。TCP再接続では変更せず、プロセス再起動時に新しく生成する
- `sequence`：同一session内の通信順序・duplicate検出
- `request_id`：Witness request/responseのcorrelation IDおよびduplicate detection ID
- `operation_id`：promotion/demotion単位のduplicate識別、冪等応答、ログ追跡

## Common envelope

Nodeメッセージの論理的なunsigned envelopeは、`CommonFields`と型付き`ProtocolMessage`から構成される。`MessageType`は`ProtocolMessage`から導出する。

```text
common, message
```

Witness request/responseは`CommonFields.request_id`を使用する。request側で生成した`request_id`をresponseがechoし、request/response correlationおよびduplicate detectionに使用する。wall clockの時刻は監査表示用でありlease安全判定には使用しない。

## Node messages

| Message | Sender → Receiver | Required payload | Response / timeout |
|---|---|---|---|
| `HELLO` | Node → peer | `priority`（CommonFieldsは別途付与） | `HELLO_ACK`、2秒 |
| `HEARTBEAT` | Node → peer | NodeState, OperationPhase, role, term, lease_id, service/health/VIP state | `HEARTBEAT_ACK`、1秒間隔 |
| `STATE_ANNOUNCE` | Node → peer | state, phase, role, term, lease_id, reason | `STATE_ANNOUNCE_ACK`、2秒 |
| `PROMOTION_INTENT` | Candidate → peer | CommonFieldsの`operation_id`、term, lease_id, priority, reason | ACK/BLOCK/UNKNOWN、2秒 |
| `PROMOTION_ACK` | Peer → Candidate | CommonFieldsの`operation_id` | 同じ`operation_id`をecho |
| `PROMOTION_BLOCK` | Peer → Candidate | CommonFieldsの`operation_id` | 同じ`operation_id`をecho |
| `PROMOTION_UNKNOWN` | Peer → Candidate | CommonFieldsの`operation_id` | 同じ`operation_id`をecho |
| `PROMOTION_COMMITTED` | Node → peer | CommonFieldsの`operation_id`、term, lease_id, Active, service/VIP state | operation event、専用ACKなし |
| `DEMOTION_INTENT` | Active → peer | CommonFieldsの`operation_id`、term, lease_id, phase, reason | `DEMOTION_ACK`、2秒（通信レベルの相関ACK） |
| `DEMOTION_ACK` | Peer → Active | CommonFieldsの`operation_id` | 同じ`operation_id`をecho |
| `DEMOTION_COMMITTED` | Node → peer | CommonFieldsの`operation_id`、term, lease_id, peer-reported service/VIP observation | operation event、専用ACKなし |

`PROMOTION_INTENT`、`PROMOTION_ACK`、`PROMOTION_BLOCK`、`PROMOTION_UNKNOWN`、`PROMOTION_COMMITTED`、`DEMOTION_INTENT`、`DEMOTION_ACK`、`DEMOTION_COMMITTED`はCommonFieldsの`operation_id`を必須とし、responseはrequestの同じ値をechoする。heartbeat断だけではpeer死亡と判定しない。stale session、stale sequence、stale term、認証失敗は破棄する。異なるまたは未知の`lease_id`はlocal情報だけでstaleと断定せず、必要に応じてWitnessのauthoritative term/lease stateへ問い合わせてreconcileする。duplicateは再度副作用を実行せず、冪等な応答だけ返す。

Protocol v1の状態値は、`service_state`が`running`/`stopped`/`unknown`、`health_state`が`healthy`/`unhealthy`/`unknown`、`vip_state`が`present`/`absent`/`unknown`のlowercase exact matchとする。`LEASE_RELEASED`の`result`は`released`、`already_released`、`unknown`のいずれかとする。`unknown`は指定leaseをauthoritative leaseとして確認できない結果、`LeaseReject`はrequest自体を受理できない場合に使用する。

将来のgraceful handoffでは、旧Activeの`DEMOTION_COMMITTED`を含むpeer observationに加え、service停止、VIP解放、lease解放を独立に確認してから新Nodeがpromotionする。現在のcommunication messageだけではresource cleanupやfencingを証明しない。

## Witness messages

WitnessはMVPでは1つであり、Witness間同期は実装しない。

| Message | Sender → Receiver | Required payload | Response / timeout |
|---|---|---|---|
| `GET_TERM` | Node → Witness | CommonFieldsの`request_id` | `TERM_STATUS`（同じ`request_id`をecho）、2秒 |
| `LEASE_REQUEST` | Candidate → Witness | CommonFieldsの`request_id`、observed_term, priority, requested_ttl, `mutation_generation` | `LEASE_GRANT`/`LEASE_REJECT`（同じ`request_id`をecho）、2秒 |
| `LEASE_GRANT` | Witness → Node | CommonFieldsの`request_id`、term, lease_id, holder, lease_ttl_ms, renew_after_ms, lease_remaining_ms | 受信確認、2秒 |
| `LEASE_RENEW` | Active → Witness | CommonFieldsの`request_id`、term, lease_id, `mutation_generation` | `LEASE_RENEWED`/`LEASE_REJECT`（同じ`request_id`をecho）、2秒 |
| `LEASE_RENEWED` | Witness → Active | CommonFieldsの`request_id`、term, lease_id, lease_ttl_ms, renew_after_ms, lease_remaining_ms | 受信確認、2秒 |
| `LEASE_RELEASE` | Node → Witness | CommonFieldsの`request_id`、term, lease_id, reason, `mutation_generation` | `LEASE_RELEASED`（result）/`LEASE_REJECT`、2秒 |
| `LEASE_RELEASED` | Witness → Node | CommonFieldsの`request_id`、term, lease_id, result | 受信確認、2秒 |
| `LEASE_REJECT` | Witness → Node | CommonFieldsの`request_id`、code、reason | なし |

Witnessは新lease発行時だけtermを増加させる。lease更新ではtermを増加させない。Witnessが状態不明またはtermを安全に復元できない場合はrejectする。

## Retry and stale handling

要求はtimeout後に再試行できる。Witness request/responseの`request_id`はCommonFieldsに置くcorrelation IDであり、requestからresponseへechoする。`request_id`でduplicateを識別し、retryされた同一requestには副作用を再実行せず、既存結果に対応するresponseを返す。認証失敗、cluster_id不一致、node_id不一致、version不一致は接続拒否とする。

leaseの相対時間はNode/Witnessそれぞれのmonotonic clockで扱う。Nodeは受信時点から安全窓を差し引いたlocal expiryを計算する。

この安全窓のdefaultは2秒であり、Node側local expiryをWitness側lease expiryより前に設定し、自己demotionを開始するための保守的な窓である。service停止・VIP解放の完了や二重Active防止を保証するものではない。

## Guarantees and limitations

プロトコルは認証済みメッセージの整合性、term・lease・sequenceの役割分離、stale/duplicateの抑止を目的とする。fencingを提供せず、peerや外部リソースの停止を証明しない。

## Canonical serialization

Protocol v1のwire encodingにはCBOR（RFC 8949 §4.2.1 Core Deterministic Encoding Requirements）を使用する。旧RFC 7049由来のlength-first orderingやRFC 8949 §4.2.3のlength-first map orderingは使用しない。

Serdeで定義されたRust型のrepresentationをProtocol v1のwire contractとして固定し、`cbor2`のcanonical encoderでdefinite-lengthかつpreferred/minimal encodingを生成する。`None`のfieldを独自にomitするcustom serializerは使用しない。

MAC対象はcanonical CBORでserializeした`UnsignedEnvelope`のbytesそのものであり、`Authentication`は含めない。認証付きwire objectは`WireMessage`全体を同じcanonical CBOR encoderでserializeするが、その結果をMAC対象には使用しない。

受信wire messageはCBOR itemを1つだけ含むことを要求し、decode後のcanonical re-encode結果と受信bytesをbyte-for-byte比較する。不一致のnon-canonical encoding、trailing bytes、2つ目のCBOR itemは拒否する。

## Transport framing

将来のTCP byte streamでは、各frameを4-byte unsigned big-endianのpayload length prefixとpayloadで構成する。lengthはprefix自身を含まず、payloadはcanonical serialized `WireMessage` bytesとする。validなpayload lengthは1..=16384 bytesであり、0および16384 bytes超は拒否する。1つのstream上に複数frameが連続して存在できるため、framing層は1つずつpayloadを切り出して後続bytesを次のdecodeへ渡す。

処理境界は`framing`、canonical decode、HMAC verify、semantic validationの順である。TCP/socket実装、timeout、connection管理はMVPの別工程とする。

同期transport readerはlength prefixを先に完全に読み、validなlengthの場合だけ最大16384 bytesのbounded payload bufferを確保する。frame開始前のEOFはclean connection closeとして扱えるが、prefixまたはpayload途中のEOFはtruncated frameであり正常終了ではない。writerはframeを書き出すが自動flushは行わず、flushはcallerの責務とする。

MVPのTCP connection primitiveは`std::net::TcpStream`を使用し、connectionへread/write timeoutを設定する。1本のTCP connection上で複数frameを連続送受信でき、clean EOFとtruncated frameを区別する。TCP layerはretry、reconnect、session、replay、member validationを行わない。production TCP listener primitiveと`PeerConnectionManager` primitiveは実装済みであり、permanent accept loopおよびdaemon統合は未実装である。

## Peer session boundary

`session_id`はMikagami process incarnationの識別子であり、`sequence`は同じ`session_id`のprocess lifetime全体でstrictly increasingとなるoutbound message sequenceである。TCP reconnectでは`session_id`もsequence namespaceもresetしない。新しいTCP connectionはHELLOから開始するが、process sessionで最初にallocateされるHELLOは通常`sequence=1`であり、reconnect時のHELLOは現在のsequenceを継続するため1固定ではない。`sequence=0`は使用しない。HELLOを受理した側はpeerの`session_id`を固定し、HELLO_ACK送信が必要であることを返す。Established後は同じ`session_id`だけを受理し、`sequence`はstrictly increasingとする。sequenceのgapは許可するが、duplicate/stale sequenceは拒否する。Established後に異なる`session_id`を受信しても同一connection上で自動切替しない。`PeerSession`は1本のlogical peer connectionにおけるconnection-localなhandshake/sequence validation boundaryであり、過去connectionのsequenceを保持しない。connectionを跨ぐreplay detectionは`PeerConnectionManager`がprocess-localな`(session_id, highest accepted sequence)`を保持して行う。bounded retired historyであり、process restart時には失われる。HMAC/Protocol validation、peer/session validation、term/lease authority validationは別々の境界であり、session boundaryはterm/lease authorityやreplay cacheを扱わない。

local process sessionの`session_id`とprocess-wide outbound sequenceは`ProcessSession`が所有する。outboundの`HELLO`はこのallocatorからsequenceを取得し、値をhardcodeしない。同じ`ProcessSession`をTCP reconnectでも再利用する。`OutboundHandshake`はconnection-localであり、HELLOを一度だけ準備し、認証済み`HELLO_ACK`を受理した場合だけEstablishedとなる。HELLO_ACKの`session_id`と`sequence`はpeer自身のprocess session namespaceに属し、sequenceは1固定ではない。sequenceが`u64`の上限に達した後はwrapせず、追加allocateを失敗させる。

TCP listener primitiveはconfigured addressへbindし、accepted `TcpStream`を既存の`TcpConnection`境界へ渡す。inbound connectionは最初に認証済みHELLOを要求し、`PeerSession`成功後にresponder自身の`ProcessSession`からHELLO_ACKを構築して送信する。outbound connectionは`OutboundHandshake`でHELLOを生成して送信し、認証・validation済みHELLO_ACKを受理した場合にEstablishedとなる。成功後の`TcpConnection`は上位runtimeへ返される。connection managerとcanonical direction arbitration、cross-connection replay registryは実装済みであり、retry、automatic reconnect、permanent accept loop、daemon統合は未実装である。

`PeerConnectionManager`はnode IDのlexical orderでcanonical directionを決める。小さいnode IDがoutbound、大きいnode IDがinboundを所有し、これはpriority、role、term、leaseとは無関係である。managerは最大1本のcanonical established connectionを保持し、同じpeer sessionではconnectionを跨ぐsequence high-waterを確認する。未知のpeer session IDはprocess incarnation候補として扱い、以前のsession IDは直近8件のbounded retired historyへ移す。history内のretired session再登場は拒否するが、history eviction後の再登場を完全には防げない。replay stateはlocal process memoryだけに保持し、term/lease authorityやfencingの代替ではない。connection lossはpeer deathを意味しない。automatic reconnect、permanent accept loop、connection managerのdaemon統合は未実装である。

HEARTBEAT/HEARTBEAT_ACKの1往復primitiveは、managerが所有するcanonical established connection上で実装されている。各messageは送信側の`ProcessSession` namespaceからsequenceを取得し、ACKはrequest sequenceをechoしない。1回のblocking heartbeatに対してoutstanding requestは1つとする。認証・validation済みのinbound heartbeatはACK送信前にpeer high-waterへcommitし、ACK送信失敗時もrollbackしない。heartbeat errorはpeer deathを意味しない。scheduler、liveness、reconnect、term/lease authority validationは未実装である。`Healthy`、`Suspect`、`Unreachable`はwire contractではなくlocal liveness classifierの観測値であり、`ProtocolMessage`へ追加しない。

established Node peer messageのruntime lifecycleは、`receive/authenticate → common peer validation → replay freshness → Pendingとして分類 → handlerのsemantic acceptance → high-water commit → side effect`とする。これはwire contractの変更ではない。Pending messageの分類だけではcommit、liveness更新、NodeState変更、authority判断または副作用を行わない。

heartbeat runtimeでは、inboundは`Pending HEARTBEAT → commit → liveness success → HEARTBEAT_ACK送信`、outboundは`HEARTBEAT送信 → AwaitingAck → Pending HEARTBEAT_ACK → commit → liveness success → Idle`の順序とする。ACKはrequest sequenceをechoせず、request_idも追加しない。

peer runtimeの1回の処理は`dispatch → HEARTBEAT/ACK、STATE_ANNOUNCE/ACK、PROMOTION_INTENT/ACK/BLOCK/UNKNOWN/COMMITTED、DEMOTION_INTENT/ACK/COMMITTEDの各専用handler → accepted PeerRuntimeStep`とする。DEMOTION_ACKはoperation_idをcorrelateした通信レベルのDemotionOutstandingを完了する。STATE_ANNOUNCEはsemantic acceptance後にhigh-waterをcommitしてからACKを送信し、peer statusを観測値として返す。STATE_ANNOUNCE_ACKは独立したoutstandingを確認してからcommitし、完了させる。これはwire contractの変更ではない。

Promotion coordinationでは、`PROMOTION_INTENT`をsemantic acceptance後にhigh-waterへcommitし、intent observationを返す。ACK/BLOCK/UNKNOWNは自動送信せず、明示的なresponse primitiveで送信する。response受信時はoutstandingの存在とoperation_id一致をhigh-water commit前に確認し、unsolicitedまたは異なるoperation_idはcommitしない。`PROMOTION_COMMITTED`はoperation eventであり、専用ACKなしでsemantic acceptance後にhigh-waterへcommitし、peer-reported observationとして返す。これらのmessageはauthorityやliveness proofではなく、PROMOTION_COMMITTEDはPromotionOutstandingをcompleteしない。

Demotion coordinationでは、`DEMOTION_INTENT`の受信に対して明示的な`DEMOTION_ACK`を同じ`operation_id`でcorrelateする。`DEMOTION_ACK`は対応する通信レベルの`DemotionOutstanding`をcompleteするが、actual demotion completion、service/VIP cleanup、lease release、peerのStandby到達、authority、fencing、またはcluster-wide resource uniquenessの証明ではない。`DEMOTION_COMMITTED`は後続のpeer-reported observation/eventであり、別の専用ACKを要求せず、semantic acceptance後にhigh-waterへcommitするが、outstandingをcompleteしない。いずれもauthorityやliveness proofではない。

Witness Runtime Stage 1では、GET_TERM/LEASE_REQUEST/LEASE_RENEW/LEASE_RELEASEをrequest、TERM_STATUS/LEASE_GRANT/LEASE_RENEWED/LEASE_RELEASED/LEASE_REJECTをresponseとして分類する。request_idをresponse correlationに使用し、semantic acceptance後にWitness側replay high-waterへcommitする。unsolicited、異なるrequest_id、またはrequestに対応しないresponse kindはcommit前に拒否する。correlated responseもterm/lease authorityではなく、専用のWitness authority decisionは未実装である。

Witness Runtime Stage 2のpersistent stateはProtocol v1 wire contractとは別物である。boot_idと同一boot内のmonotonic deadlineを復元し、boot_id不一致や不整合時はNotReadyとして扱うが、GET_TERM等のmessage handlerへ接続せず、term/lease decisionも行わない。

Witness Runtime Stage 3では`GET_TERM`をread-only authority pathへ接続する。`TERM_STATUS`は`CommonFields.term == payload.current_term`かつ`CommonFields.lease_id == payload.current_lease_id`を満たさなければならない。Readyでない場合、またはReadyでも`LeaseState::Unknown`の場合はTERM_STATUSを生成せず、Protocol v1にNotReady用responseは追加しない。wire representationは変更しない。

### Stage 3.9 LEASE_REQUEST authority policy

Stage 4の`LEASE_REQUEST` authority policyでは、NewEligible requestの`observed_term`はWitnessの`current_term`と完全一致しなければならない。過去または未来のtermはdeterministic `LEASE_REJECT`とし、成功時だけWitnessが`current_term.checked_add(1)`でtermを進める。`current_term == u64::MAX`もdeterministic rejectである。

MVPのTTL policyは固定で、`requested_ttl == 10_000ms`だけを許可し、grantは`lease_ttl_ms = 10_000ms`、`renew_after_ms = 3_000ms`とする。異なるTTLはdeterministic rejectであり、clampやnegotiationは行わない。新しいlease_idはWitnessがOSのCSPRNGから独立したcanonical UUIDv4として生成する。

`LeaseState::None`だけが新規grant候補である。`Active`はpriorityに関係なくdeterministic reject、`Unknown`はauthority-readiness failureとしてpre-commit fail closedとし、term・journal・watermarkを変更しない。deterministic rejectはauthority stateを変更せず、journalとwatermarkを同一atomic commitする。Conflict、Retired/Stale、GenerationGapはjournal classificationから構造的に`LEASE_REJECT`へ写像し、authority state・journal・watermark・generationを変更しない。NotReady、clock/CSPRNG/persistence failure、JournalFull等は安全な相関responseを生成できる場合だけ`TEMPORARILY_UNAVAILABLE`を返し、それ以外はresponseなしとする。

Duplicateの`LEASE_REJECT`はauthorityを再実行せず保存済み結果を再送する。Duplicateの`LEASE_GRANT`は、current Active authorityのterm・lease_id・holder・lease TTLが保存済みgrantと一致し、current durable authorityにmonotonic deadlineが存在する場合だけ再構築できる。stored grantのabsolute deadlineとの比較は要求せず、`lease_remaining_ms`はcurrent monotonic deadlineから再計算する。remainingが0、またはidentity不一致ならfail closedとする。いずれもterm、lease、journal、watermarkを変更しない。Retired/Staleは過去のgrantを証明せず、GenerationGapはgenerationをconsumeしない。

### Stage 4.9 LEASE_RENEW authority policy

Stage 5のLEASE_RENEW authorityは、現在の`Active` leaseについて、requestのterm・lease_id・requester(holder)がcurrent authorityと一致し、TTLが10,000ms、deadlineが存在し、`now < deadline`の場合だけ成功候補とする。`None`、`Unknown`、期限切れ、identity不一致、TTL不正はそれぞれ仕様に従い、Unknownやmetadata欠落などの不確実性はpre-commit fail closedとする。

成功renewalはterm・lease_id・holderを変更せず、`new_deadline = now.checked_add(10_000ms)`で更新する。`LEASE_RENEWED`はcurrent term・lease、TTL 10,000ms、renew_after 3,000ms、remaining 10,000msを返す。deadline、journal、watermarkは同一candidateの一回のatomic save後にのみ応答する。期限切れのActiveをNoneへ変更したり、renewalで復活させたりしない。

Duplicate `LEASE_RENEWED`はdeadlineを再延長せず、current Active authorityのidentityとdeadlineを検証してremainingを再計算する。後続renewalでdeadlineが新しくなっていても、stored resultのabsolute deadlineとの一致は要求しない。remaining zeroまたはidentity不一致はfail closedとする。Stage 5のLEASE_RENEW authorityは実装済みであり、LEASE_RELEASE authorityおよびexpiry processingは未実装である。

Mutating Witness request（`LEASE_REQUEST`、`LEASE_RENEW`、`LEASE_RELEASE`）の`request_id`は128-bit cryptographically random UUID相当のlogical request identityとし、別のlogical requestへ再利用しない。同一requestのretryだけが同じ`request_id`を使用でき、session_id/sequenceが異なってもrequest kind、requester、semantic payloadが同じなら同一retryである。request_id journalによるdurable idempotencyはsession/sequence replay protectionとは別の境界である。bounded journalのeviction後も安全にretirementを証明するため、Protocol v1のfreezeを一時的に解除し、mutating request payloadへ`mutation_generation`を追加する仕様訂正を行った。

### Stage 5.9 LEASE_RELEASE authority policy

Stage 5.9では、将来のLEASE_RELEASE authority実装に向けたpolicyを固定する。NewEligible requestは、WitnessがReadyで、lease stateがActive、requestのterm・lease_id・requesterがcurrent authorityのterm・active lease・holderと一致し、authority metadataが整合している場合だけrelease候補となる。期限の確認やmonotonic clock readは要求しないため、期限切れのActiveでも一致するreleaseは許可候補である。`LeaseState::None`は過去のreleaseの証明ではなく、deterministic `LEASE_REJECT(POLICY_REJECT)`とする。Unknown、metadata不整合等はpre-commit fail closedとする。Conflict、GenerationGap、RetiredStaleはStage 9.9.2のtyped `LEASE_REJECT`として返し、authority state・journal・watermarkを変更しない。

成功candidateはtermを変更せず、lease stateとactive lease_id、holder、TTL、deadlineをすべてNoneにし、`LeaseReleased`（result `released`）journal resultとrequester watermarkを同じatomic saveでcommitする。commit後にだけ`LEASE_RELEASED`を返し、そのCommonFieldsはpost-release authorityとしてcurrent termと`lease_id = None`を表す。Duplicateの成功結果・rejectは保存済み結果を再送し、current authorityを再評価・変更しない。歴史的な成功payload（release対象のterm/lease_id）は、response envelopeが後続のcurrent term/lease_id（またはNone）を表していても、完全一致するdurable outstandingに対するDuplicateならNode側で受理できる。これはそのrelease mutationのcommitだけを証明し、現在のauthority不在、service/VIP cleanup、fencingを証明しない。後で別leaseがActiveになっても、過去の成功releaseのreplayがそれをclearすることはない。send failure後もcommitをrollbackしない。

LEASE_RELEASEはfencing、service停止、VIP解放、host停止の証明ではなく、Nodeのlocal demotionもWitness responseを待たない。Stage 6でLEASE_RELEASE authorityを実装済みとするが、expiry processingとNode allocatorは未実装である。

### Stage 6.9 Witness lease expiry processing policy

Stage 6.9では、Witness-local authority maintenanceとしてのlease expiry policyを固定する。expiryはProtocol v1 requestではなく、新しいmessage、request_id、mutation_generation、watermarkを持たない。expiry candidateはWitnessがReadyで、LeaseStateがActive、authority metadataとsame-boot monotonic deadlineが完全に整合し、clock readが成功して`now >= deadline`となる場合だけ作成する。`now < deadline`はno-op、`now == deadline`と`now > deadline`はexpiredである。Noneはno-op、Unknown、NotReady、metadata不整合、clock failureはfail closedとし、推測による修復を行わない。

成功expiryはtermを変更せず、Active leaseのlease_id・holder・TTL・deadlineをすべてNoneにして、既存のatomic durable saveでcommitする。journal records、generation watermarks、retirement metadataは変更しない。expiryはjournal eventでもresponseを伴うmutationでもなく、永続化失敗時は旧Activeを維持する。expired Activeに対するGET_TERMはexpiryが未処理ならremaining 0を返し、expiry commit後は同じtermのNone authorityを返す。LEASE_REQUESTはexpired Activeを暗黙にclearせず、独立したexpiry commit後だけ新termのgrant候補となる。

expiry、LEASE_RENEW、LEASE_RELEASEは同一のdurable authority snapshotを直列化して評価・commitし、stale snapshotによるrenew後のclearやexpiry後のrenew resurrectionを許可しない。先にcommitしたreleaseまたはexpiryだけがActiveをNoneにし、後続処理はcurrent stateに従う。過去のDuplicate LeaseReleasedだけはjournal resultを歴史的に再生し、LeaseGrant/LeaseRenewedのDuplicateはexpiry後のNone authorityではfail closedとなる。expiryはfencing、service/VIP停止、peer死亡、実リソース唯一性を証明しない。

Stage 7でWitness lease expiry maintenance primitiveを実装済みであり、Stage 8でそのscheduler/runtime integrationを実装済みである。Protocol v1はFROZENのまま維持する。

### Stage 9.9.2 Typed Witness mutation outcome protocol correction

Stage 9.9.2でProtocol v1を一時的にunfreezeし、`LeaseRejectPayload`へtyped outcome codeを追加した。実装・tests・golden vector確認後、Protocol v1を再freezeした。pre-correction Protocol v1 wireとの互換は提供しない。成功は既存の`LEASE_GRANT`、`LEASE_RENEWED`、`LEASE_RELEASED`のままである。

```text
POLICY_REJECT
RETIRED_STALE
CONFLICT
GENERATION_GAP
TEMPORARILY_UNAVAILABLE
```

`POLICY_REJECT`はdurable deterministic reject、`RETIRED_STALE`はgenerationがwatermark以下だが元結果は不明、`CONFLICT`はjournal identity conflict、`GENERATION_GAP`はwatermark+1を飛び越えたrequest、`TEMPORARILY_UNAVAILABLE`はterminal durable result未確定の安全側結果を表す。reason文字列は診断用であり、Nodeは文字列をparseしてはならない。

現在のdeterministic rejectは、LEASE_REQUESTのobserved term不一致、TTL不正、Active authorityによるpreemption、term exhaustion、LEASE_RENEWのActive不在・term/lease/holder/TTL不一致または期限切れ、LEASE_RELEASEのActive不在・term/lease/holder不一致である。これらのdurable rejectと、そのDuplicate replayは`POLICY_REJECT`へ写像する。`RetiredStale`、`Conflict`、`GenerationGap`はWitness journal classificationからそれぞれ`LEASE_REJECT(RETIRED_STALE)`、`LEASE_REJECT(CONFLICT)`、`LEASE_REJECT(GENERATION_GAP)`へ構造的に写像する。JournalFull、NotReady、Unknown authority、clock/CSPRNG/deadline/persistence failure、authority lock poison等は安全にresponseを作れる場合だけ`TEMPORARILY_UNAVAILABLE`、それ以外はresponseなしとする。

| Witness result | Wire outcome | Node action |
| --- | --- | --- |
| typed success (`LEASE_GRANT`/`LEASE_RENEWED`/`LEASE_RELEASED`) | existing typed response | clear as `AcceptedSuccess` |
| new or duplicate deterministic reject | `LEASE_REJECT(POLICY_REJECT)` | clear as `DeterministicReject`; successとは扱わない |
| `RetiredStale` | `LEASE_REJECT(RETIRED_STALE)` | queueだけclearし、必ずreconcile |
| `Conflict` | `LEASE_REJECT(CONFLICT)` | retain; RecoveryPending/admin reconcile |
| `GenerationGap` | `LEASE_REJECT(GENERATION_GAP)` | retain; generation jump/rewrite禁止 |
| JournalFull等のpre-commit failure | `LEASE_REJECT(TEMPORARILY_UNAVAILABLE)`またはresponseなし | retain; exact retry |
| response loss、timeout、相関・認証・replay・malformed failure | no terminal outcome | retain; exact retry |

`LEASE_REJECT`は3種類のmutating requestに共通して使用し、`mutation_generation`をresponseへ追加しない。Nodeはdurable outstandingのrequest_id、generation、kind、payloadをlocal contextとして保持する。request_id/kind correlationに失敗したresponseはclearしない。`LEASE_RELEASED`はWitness authorityのreleaseだけを示し、service/VIP cleanupやfencingを証明しない。`RETIRED_STALE`のrenewはlocal deadlineを延長せず、requestの成功を推測しない。

Stage 9のNode actionは、成功responseと`POLICY_REJECT`をclear、`RETIRED_STALE`をqueue terminalとしてclearする。ただしRetiredStaleはsuccess proofではなくreconcileを要求する。`CONFLICT`と`GENERATION_GAP`はoutstandingを保持してRecoveryPending/admin reconcile、`TEMPORARILY_UNAVAILABLE`とresponseなしは同一request_id・generation・payloadを保持してretryする。responseのrequest_id/kind correlationに失敗した場合もclearしない。responseへ`mutation_generation`は追加せず、Nodeのdurable outstandingをlocal contextとして使用する。

`LeaseRejectPayload`のwire形は`{ code: WitnessMutationOutcomeCode, reason: String }`である。codeはcanonical CBORへ含まれ、UnsignedEnvelope全体のHMAC対象となる。unknown codeはdecode/semantic validationでfail closedとし、reasonは診断情報であり分類には使用しない。`mutation_generation`はresponseへ追加していない。Witness persistent v2、journal、watermark、Node persistent v1の形式と意味は変更していない。永続journal内の旧LeaseRejectはreasonのみを保持し、duplicate response再構築時に`POLICY_REJECT`として扱う。

### Stage 2.0.2 request generation and retirement proof

既存の`LEASE_REQUEST`の`observed_term`、`LEASE_RENEW`の`term + lease_id`、`LEASE_RELEASE`の`term + lease_id`だけでは、bounded journalからrecordをevictした後に、古いretryと新しいlogical mutationを安全に区別できない。したがって3種類のmutating requestは、requester nodeごとのdurableな単調増加論理値`mutation_generation: u64`（1以上）を持つ。新しいlogical requestは値を増加させ、retryは同じ値を再利用する。これは`request_id`、`session_id`、transport `sequence`、`operation_id`とは別の値である。

`request_id`はmutating Witness requestについて、128-bit CSPRNGによるUUID v4、RFC 4122/RFC 9562互換variant、lowercase ASCIIのhyphenated 36文字形式に固定する。uppercase、brace、URN、hyphenなし、whitespace、nil UUID、v4以外または不正variantは拒否する。この形式制約はmutating requestに適用し、GET_TERMの既存request_id規則は変更しない。

Witnessはrequesterごとに`highest_committed_mutation_generation`をdurably保持し、authority state、journal、retirement metadataと同じatomic durable saveで更新する。active journal recordがある場合は、request kind、requester、fingerprint、generationが一致するretryだけをDuplicateとして既存結果から再構築し、それ以外はConflictとする。journal missだけでは未commitの証明にならない。missしたrequestは、generationがdurable watermark以下ならRetired/Stale、`watermark + 1`と一致する場合だけNewEligible候補、`watermark + 1`を超える場合はGenerationGapとして拒否する。

fingerprintにはrequest kind、requester、semantic payload、`mutation_generation`を含め、request_id、session_id、sequence、operation_id、MACおよび配送状態は含めない。journalは最大64件のbounded active/recent recordを維持し、retirement proofのないrecordはevictしない。安全にretireできるrecordがない場合はJournalFullとしてfail closedにする。Retired/Staleでは安全な拒否だけを行い、active recordのような結果再送は約束しない。

この仕様訂正により一時解除されていたProtocol v1 wire freezeを再freezeした。`mutation_generation`を含むwire型、canonical CBOR、HMAC対象、fixed vectorおよびtestsを更新済みであり、Protocol v1をv2へ改名しない。Stage 2.1 durable journalとStage 4 `LEASE_REQUEST` authorityはこのwire contract上に実装済みである。

### Stage 2.0.3 generation allocation and crash recovery

`highest_committed_mutation_generation`は、requesterごとに1から連続してdurably closedされたhigh-water markである。新規mutationの候補は厳密に`generation == watermark + 1`だけとし、`generation <= watermark`のjournal missはRetired/Stale、`generation > watermark + 1`は`LEASE_REJECT(GENERATION_GAP)`としてfail closedにする。watermarkが`u64::MAX`の場合およびgeneration 0の場合も新規mutationを拒否し、自動reset・wrap・term/lease/process/OS lifecycleによるリセットは行わない。namespaceはrequester node_idごとに独立する。

generationのallocatorはrequester Nodeが所有する。Nodeは、generation counterとoutstanding mutation（request_id、generation、kind、完全なsemantic payloadまたは再構築可能な情報）を同一のdurable candidateとしてatomic saveし、persist成功前に送信しない。requesterごとにmutating Witness logical requestは最大1件とする。Node restart後は未解決outstandingを同じrequest_id、generation、kind、payloadで再送し、新しいgenerationを割り当てない。送信前crash、partial send、response loss、response受信後のlocal clear前crashはいずれもこのretry pathを使用する。

Witnessのdurable terminal decision（successまたはdeterministic reject）はgenerationをconsumeし、watermarkを連続して進める。NotReady、clock failure、persistence failure、transport failureなどcommit前のtransient failureはconsumeしない。Witnessのdurable commit後のresponse送信失敗はconsume済みであり、journalが残っていればDuplicateとして結果を再構築する。

response受信時はauthentication、semantic validation、outstandingとのrequest_id/kind/generation相関を確認し、terminal resultを受理してからNodeのdurable bookkeepingを更新し、outstandingをclearして次generationを許可する。Retired/Staleは副作用非実行を示すterminal safety resultであり、元のsuccess結果の証明ではない。LEASE_REQUESTはGET_TERM等で現在のterm/lease/holderを再観測し、元のgrantと区別できなければgrantとして扱わずRecoveryPendingとする。LEASE_RENEWは現在leaseの観測で旧renew成功を推測せず、期限延長として扱わない。LEASE_RELEASEのdurable Duplicateは、歴史的payloadがexact outstandingと一致する場合に限りAcceptedSuccessとしてcompletionできるが、現在のauthority不在やresource cleanupの証明ではない。これらは永久result historyを要求せず、安全側に停止する。

local expiryまたはその他の安全上のdemotionは、one-outstandingのWitness mutation queueやLEASE_RELEASE responseを待たず、service停止・VIP解放を直ちに開始する。Witness requestのretired resultを受けた場合もlocal resourceの成功を推測しない。

Stage 2/3からの明示的migrationでは、Stage 4 authority未実装というhistorical invariantを検証したうえでknown requesterのwatermarkを0から開始する。Node側generation stateを失った場合、同じnode_idのwatermarkから自動再生成せず、既存のFailed/RecoveryPendingおよび管理者reconcileを使用する。Witnessのvalidな古いsnapshotへのrollbackは、boot_idやatomic write検証だけでは一般に検出できない。この制限を解消する追加wire fieldやTPM等はStage 2.0.3では導入しない。

durably committedなmutating requestはjournal retention中、同じsemantic identityのretryに対して副作用・term increment・lease生成を再実行せず、committed semantic resultからresponseを再構築する。同じrequest_idでkind、requester、fingerprintのいずれかが異なる場合はConflictであり、新規requestとして処理しない。journal missは未commitの証明ではなく、retirement proofがない限り新規mutationを許可しない。evictionはauthority generationとdurable retirement watermark等で安全にretireできるrecordだけを対象とし、該当recordがなければavailabilityを犠牲にして拒否する。

Witness internal persistent formatはProtocol versionとは別に`state_format_version = 2`を使用する。legacy Stage 2/3 stateはStage 4未実装という今回限りのhistorical invariantを検証した明示的migrationでempty journalへ変換する。v2でjournal fieldが欠落、unknown future version、またはdowngradeとなる場合はfail closedとする。wire responseのretry時は、現在のProcessSessionからsession_idとsequenceを割り当て、HMACとdynamicなremainingをその送信ごとに構築する。logical retryが新しいProcessSessionやsession_idを要求するわけではなく、wire bytes自体をjournalへ保存しない。

### GET_TERM / TermStatus semantics (Stage 13.3 clarification)

Wire format is unchanged. Semantic clarification only:

- GET_TERM is read-only and does **not** execute lease expiry.
- `current_holder = None` means Witness `LeaseState::None` (no holder
  recorded). It does not prove peer death or resource release.
- `current_holder = Some(node)` with `lease_remaining_ms = 0` means
  expired-but-unprocessed Active metadata. Clients must not treat this as
  `None` and must not authorize failover from it.
- `current_holder = Some(node)` with `lease_remaining_ms > 0` is an
  unexpired holder view at the Witness.
- Expiry transitions holder to `None` only through the existing Witness
  expiry maintenance commit.
