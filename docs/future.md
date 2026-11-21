# Future Scope

> 開発者向けの設計・検証の記録です。開発の工程の識別子（段階や判断の番号）と、公開候補に含まれない内部の資料への参照を含みます。利用の手順は [`README.md`](../README.md) と [`configuration.md`](configuration.md) を参照してください。

以下はMVPの対象外である。

- 汎用の`command`以外の既製のfencing backend（v1.0で`fencing.backend = "command"`を提供した。GCEのhelper `mikagami-gce-fence`はv0.7で検証の構成として扱い、既定のbuildに含めない。本番への配線はv0.7の対象外で、本番の意味と範囲（D-2）は後の版で決める。[`gce-fencing.md`](gce-fencing.md)）
- AWS対応
- AWS Secondary Private IP、ENI、Elastic IP
- AWS EC2 stop/force stopによるfencing
- Redfish/IPMI
- libvirt
- その他cloud NetworkBackend
- 複数Witness
- Witness間同期
- 複数VIP
- 複数service group
- 自動failback
- rolling upgradeとprotocol version互換
- TLS
- PSK rotation
- 内部GARP実装
- 汎用plugin framework
- 非同期backend向け汎用workflow基盤

AWSでは、Secondary Private IP、ENI、Elastic IP、EC2 fencing等が将来の候補になり得る。ただし今回AWS実装仕様は設計しない。

同一AZでのENI/private IP切替と、Multi-AZ HAは同一ではない。可用性、ネットワーク到達性、障害ドメイン、fencingの要件は別途検討が必要である。

## Deferred decisions

以下はMVP後まで延期する。

- cloud backendの具体API
- fencingの各実装方式（汎用の`command`とGCEのhelperの候補を除く）
- 複数Witnessの合意方式
- TLSと証明書運用
- PSK自動rotation
- rolling upgrade
- 内部GARP実装

## v1.0で設定から削除したもの

次のキーはv1.0の設定に存在しない（書くとエラー）。内部の定数として導出されるか、機能自体が未対応である。

- `cluster.mode`（常にconservative。`availability`モードは提供しない）、`cluster.heartbeat_port`（`node.listen`から導出）
- `node.priority` / `peer.priority`（`node.preferred`から導出: 100/50）、`node.bind_address`
- `[heartbeat]` / `[lease]`（固定の定数: heartbeat 1秒・unreachable 10秒・lease TTL 10秒・更新3秒）
- `[hooks]`、`[logging]`、`[timeouts]`、`health.interval_sec`、`security.require_*`、`witness.enabled`

その他の未対応: Activeの間のhealthやserviceの異常による降格・再起動・切替（警告のログだけ。v1.0 D-5）、稼働中デーモンの内部状態を表示する`status`（Owner判断で保留）、Witness状態の巻き戻し検出、再起動をまたぐfence回数の厳密な上限、自動failback。
