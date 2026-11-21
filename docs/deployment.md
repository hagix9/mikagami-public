# Deployment

2台のノード（node-a、node-b）と、その2台ではない第3のホスト（Witness）が要る。この文書の手順は`contrib/`の例を前提にする。**Linux実機（別ホスト）での受入は未実施**であり、手順の各コマンドはまだ実環境で通しで検証されていない（[`testing.md`](testing.md)）。

## 1. 共通の準備

1. 3台すべてに同じ`mikagami`バイナリを`/usr/local/bin/mikagami`として置く。
   Rocky Linux 9 / 10 では、代わりにRPM（`mikagami-0.8.0`、`/usr/bin/mikagami`とunitを`/usr/lib/systemd/system/`に置く）を使える。導入・更新・削除の手順と安全の規則は[`rpm.md`](rpm.md)。RPMのunitを使う場合、以下の`install ... /etc/systemd/system/`の手順は不要である。
2. PSKを**1回だけ**作り、3台に同じファイルを配る。形式は64文字の16進数（小文字）、権限は`0600`、所有者はroot:root。
   ```sh
   umask 077
   head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > /etc/mikagami/cluster.psk
   chmod 600 /etc/mikagami/cluster.psk
   ```
   PSKの内容は設定・引数・ログのどこにも出ない。鍵の更新（rotation）は未対応で、変える場合は3台すべてを止めて同時に差し替える。
3. ファイアウォールで、node-b（Inbound）の`node.listen`のポートにnode-aから、Witnessの`listen`のポートに両ノードから届くようにする。

## 2. Witness

```sh
install -m 0600 contrib/examples/witness.toml /etc/mikagami/witness.toml   # 編集する
mikagami witness init --config /etc/mikagami/witness.toml   # 状態を1回だけ作る
install -m 0644 contrib/systemd/mikagami-witness.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now mikagami-witness
```

- `witness init`は既存の状態があれば拒否する（termが0に戻ることはない）。
- **状態ディレクトリをバックアップから復元してはならない。** 古い状態に戻ったWitnessは検出できず、termの巻き戻しは安全性の前提を壊す。復元が必要な場合は、両ノードを止めてから行い、運用者が責任を持つ。
- ホストの再起動後、有効なleaseが残っていれば自動で再武装される（`on_reboot = "rearm"`）。`refuse`にした場合や、状態が古すぎる場合は、Witnessは起動を拒否する。状態が**復元されたものでない**ことを確認してから`mikagami witness rearm --config ...`を実行する。

## 3. ノード（node-a と node-b）

```sh
install -m 0600 contrib/examples/node-a.toml /etc/mikagami/mikagami.toml   # node-bはnode-b.toml。編集する
install -m 0644 contrib/systemd/mikagami.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now mikagami
```

- **管理対象のservice（例では`nginx.service`）を起動時に有効化しない**（`systemctl disable nginx`）。Mikagami以外の何も、そのserviceやVIPを起動してはならない。`Restart=`も付けない。この前提が破られると、冷起動の安全判定は外部の起動を検出できない。
- 自動切替（peer喪失時のfence）を使うには`[fencing] backend = "command"`が必要。`fence`は「peerを隔離状態にする」冪等な操作で、電源のトグルではないこと。`verify`は隔離を確認して終了する。いずれもroot所有の絶対パス、argv配列。
- 起動直後はStandbyになる。デーモンの最小稼働時間（30秒）の後、両ノードがStandbyで健全な状態が続くと、`node.preferred`のノードが約20秒後（起動から約50秒）、もう一方がさらに約15秒後（約65秒）に、Activeになるよう要求を出す（ログに`bootstrap admission`の行が出る）。手動でも`systemctl kill --kill-whom=main -s USR1 mikagami`を**2回**送ることで同じ手順を進められる（1回目で基準を取り、peerの応答を待ってから2回目）。

## 4. 運用

### 状態の確認

```sh
mikagami status --config /etc/mikagami/mikagami.toml
journalctl -u mikagami -o cat
```

`status`は設定と永続状態だけから作る読み取り専用の報告で、動作中のデーモンの内部は見ない。**正常時のログは無音**で、状態遷移（peerの喪失・復帰、health、自動切替の開始・停止、起動時の整合）だけが1回ずつ出る。

### peerが落ちたとき

`fencing.backend = "command"`で、このデーモンがpeerをActiveとして観測していた場合に限り、約10秒後に自動でfence→verify→昇格の手順に入る。`FAILED`（peerが隔離されていない）や予算超過ではそこで停止し、ログに`automatic failover stopped`と理由が出る。その場合は人が判断する:

1. peerが本当に止まっていることを確認する（電源・ハイパーバイザ）。
2. `mikagami recover <service> --confirm-fenced <peer-node> --incident <seq> --config ...`で隔離を属人的に証明し、
3. `systemctl kill --kill-whom=main -s USR1 mikagami`で昇格を要求する。

### 再起動

- デーモンはWitnessとの接続を失い、かつ資源を持たないStandbyのとき、非0で終了して`systemd`に再起動させる（再接続のため）。Activeのときは自分のleaseの失効で降格してから終了する。
- クラッシュした旧Activeは、再起動時に**起動時整合**（SOR）で自分の解放義務を解消してStandbyに戻る。Witnessのtermが自分の記録より古い、または同じtermで他者がholderのときは解消せず、ログに`recovery gate blocked startup`と原因が出る。この場合は運用者が状態を確認する。
- 再起動をまたいだfence回数の厳密な上限はない（再起動のたびに予算は初期化される）。fenceコマンドの冪等性が運用条件になる。

### 起動時の照合で止まったとき

post-cleanupのRelease / Renewの照合で降格の後に止まった（latch）nodeを、運用者の再起動で起動時の照合（SOR）に回す手順である。昇格は含まない。v0.7ではlatchは再起動なしに解消する（実daemonのE2Eで確認）ので、この手順はそれでもlatchが残った時の手動の手順である。

1. 再起動してよい前提（すべて）：VIPが無い（P-1）。管理するserviceが停止している（P-2）。`mikagami status`がReleaseの保持（`outstanding(LeaseRelease)`または`release obligation armed`）を示す（P-3）。daemonは動いているがActiveではない（P-4。PolicyRejectによるlatchはログを出さないことがあるので、P-1〜P-3で判断する）。相手のnodeの状態が分かっている（P-5）。**Witnessに到達できる（P-6、必須）**。
2. 再起動してはいけない：VIPがある、serviceが動いている、`status`が`unreadable`または`node.role: unknown`、daemonがActiveで通常のRenewをしている、Witnessに到達できない、同じnodeで直前の再起動が失敗している。
3. 手順：前提の出力を記録する → `systemctl stop <unit>`（`shutdown requires unresolved resource cleanup`でexit 1は正常）→ `systemctl start <unit>` → 30秒以内に`startup reconciliation resolved the release obligation of term N: ...`が出ることを確かめる → `status`がclean、VIPが無い、serviceが停止。
4. 起動の失敗が続いてunitが`failed`（start limit）になったら、原因（Witnessへの到達、設定）を直した後に、`systemctl reset-failed <unit>` → `systemctl start <unit>`を1回だけ行い、照合のログを確かめる。照合が`Blocked`のまま、または起動の直後に再びlatchした時は、再起動を繰り返さずに止めたままにし、Witnessのterm・holderとnodeの`status`を記録して判断を仰ぐ。
5. latchの検出はログだけに頼らない。`status`のReleaseの保持、VIPが無いこと、serviceの停止の組み合わせで検出する。
6. latchの間のdaemonは、localに現れたVIPやserviceを除かない。資源が予期せず現れたら直ちに`systemctl stop`し、二重のActiveの疑いとして調べる。
7. 時間の条件：相手がActiveの間は、Witnessのjournal（64件）がこのnodeのReleaseの記録を消す。v0.7では消えた後の再起動もC-lで解消しうる（新しいtermが示される場合）が、解消しない場合もある（例：viewが自分を期限の残るholderと示す）。早く行うほど、exactな結果（PolicyReject）の経路を通る。本番の時間の窓は確かめていない。
8. ログの`see mikagami recover`は、fencingの隔離の証明のcommandを指す。この場面（起動時の照合）には使わない。

### Witnessの状態の取り扱い

- Witnessの`state_dir`をbackupから戻してはならない。
- Witnessのhost・diskを古いVMやdiskのsnapshot（memoryを含むsnapshotを含む）に戻してはならない。
- 状態を失ったWitnessは、文書にしたcluster全体の復旧と一緒にだけ初期化する。
- `on_reboot = "refuse"`は補助策で、巻き戻しの検出の手段ではない。止めるのはboot idの違う状態の自動の再武装だけで、同じbootの間に取った写しの復元とVMのmemoryごとの復元は止めない。状態ファイルのmtimeの確認も復元の検出ではない。
- `mikagami witness rearm`を明示に実行する前に、Witnessのstate fileの`current_term`と`generation_watermarks`を、各nodeのstate fileのOのtermと`highest_started_mutation_generation`、および各nodeのログに出た最大のtermと、人が照合する。いずれかのnodeがより大きなtermか、watermarkを越えるgenerationの完了を知っていれば、rearmしない。この照合は自動の再武装（`on_reboot = "rearm"`）には掛からない。

### 永続化の前提

nodeとWitnessの状態の耐久性は、OS、filesystem、diskがfsyncとrenameを守ることに依る。受け入れた範囲と運用の条件は[`persistence.md`](persistence.md)の「v0.7 追補」のP-fsの項のとおり（試験したimage・filesystem・mountの条件を変える場合は、その前提の外になる）。

### アップグレード

互換性の約束はまだない（protocolのバージョン互換・rolling upgradeは未対応）。3台すべてを止め、バイナリを差し替えて、Witness→node-b→node-aの順に起動する。

2ノード構成では、2台とも止めてからバイナリ（と共通設定）を差し替え、両方を起動する。共通設定（`[nodes.<id>]`）の`Hello`は前の版には読めないので、片方だけを新しい版にすると2台は接続しない。新しい版の側はこれを設定の不一致として扱う（自動の切替をしない）が、**前の版の側は通信断として扱う**（相手をActiveとして見ていれば、fenceの確認の後に引き継ぎうる）。必ず2台とも止めてから更新する。

## 5. 既知の制約

- 既知の制約と未検証事項は[`../README.md`](../README.md)の「既知の制約」、[`safety-model.md`](safety-model.md)、[`../TWO_NODE_SAFETY_MODEL.md`](../TWO_NODE_SAFETY_MODEL.md)にある。
