# Security

> 開発者向けの設計・検証の記録です。開発の工程の識別子（段階や判断の番号）と、公開候補に含まれない内部の資料への参照を含みます。利用の手順は [`README.md`](../README.md) と [`configuration.md`](configuration.md) を参照してください。

## PSK

PSKはTOMLへ直接書かず、専用ファイルから読み込む。PSKは256bit、32バイトの暗号学的乱数とし、64文字のlowercase hexで保存する。複数行、不正文字、長さ不一致は拒否する。

推奨permissionは`0600`、所有者はroot、所有グループもrootとする。symlinkは拒否または実体の所有者・permissionを検証する。

MVPのPSK loaderはsymlinkおよびregular fileでない対象を拒否し、Linuxでは`0600`かつroot所有・rootグループを要求する。macOS開発環境ではroot所有・rootグループの強制を行わず、permission検証までとする。

## Message authentication

HMAC-SHA-256を使用する。MAC inputは以下を唯一の正規定義とする。

```text
HMAC input =
CborSerializer::serialize_unsigned(&UnsignedEnvelope)
```

`UnsignedEnvelope`は`CommonFields`と`ProtocolMessage`から構成される。`request_id`や`operation_id`を含むCommonFieldsの値は、存在する場合はcanonical CBOR bytesに含まれ、HMAC対象となる。`message_type`はCommonFieldsに独立して保持せず、`ProtocolMessage`のSerde representationがmessage種類を表現するため、その情報もserializationを通じてMAC対象に含まれる。`Authentication.mac`は`UnsignedEnvelope`の外側にあるためMAC対象外である。

Protocol v1ではCBOR（RFC 8949 §4.2.1）のdeterministic encodingを使用し、Serde representationをwire contractとして固定する。

MAC比較はconstant-timeで行う。

## Session and replay

HELLOもHMAC認証する。HELLOでprotocol version、cluster_id、node_idを確認する。`session_id`はMikagamiプロセス起動時に一度、OS CSPRNGから128bit以上の乱数を取得してlowercase hex文字列として暗号学的にランダム生成する。安全性のないfallbackは使用しない。TCP再接続では変更せず、プロセス再起動時に新しい`session_id`を生成する。`sequence`は同じprocess session_idのprocess lifetime全体で単調増加させ、TCP再接続でリセットしない。

古いsession、既処理sequence、古いterm、古いlease_idは破棄する。request_idとoperation_idで要求・操作単位のduplicateを排除する。

connectionを跨ぐpeer session/sequenceのreplay判定はHMACとは別のruntime boundaryであり、process-localなbounded memoryで行う。永続化せず、term/lease authorityやfencingの代替ではない。

## Encryption and rotation

MVPでは通信暗号化を行わない。HMACは認証・改ざん検知を提供するが、内容を秘匿しないため、管理ネットワークまたはVPNの利用を推奨する。

PSKの自動rotationはMVPでは実装しない。PSK変更はNodeとWitnessを停止またはmaintenanceにして同時更新する運用とする。

## Guarantees and risks

PSK漏洩時は通信の認証・完全性が失われる。process compromise、root侵害、誤ったpermission、管理ネットワーク侵害はMVPの暗号仕様だけでは防止できない。
