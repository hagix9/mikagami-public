# RPM パッケージ（Rocky Linux 9 / 10）

RPM `mikagami-0.8.0-N.elX` の導入、更新、削除の手順と、パッケージ管理が守る安全の規則。ビルドの手順は [`packaging/rpm/README.md`](../packaging/rpm/README.md) にある。**実機の Rocky Linux 9 / 10 での導入・更新・削除の試験の結果は [`packaging/rpm/README.md`](../packaging/rpm/README.md) の記録を確認すること**（未実施の版では、ここに書いた振る舞いは spec と scriptlet の試験だけで確かめたものである）。

## 内容

| path | 内容 |
|---|---|
| `/usr/bin/mikagami` | バイナリ（Witness 構成と 2 ノード構成の両方） |
| `/usr/libexec/mikagami/check-http` | HTTP の health check の script（`[health] command` に使う。curl を使う） |
| `/usr/bin/mkg` | `mikagami` への相対の symlink。同じ CLI（[`cli-command-names.md`](cli-command-names.md)） |
| `/usr/lib/systemd/system/mikagami.service` | ノードの daemon（`daemon run`。`cluster.topology` に従い Witness 構成か 2 ノード構成で動く） |
| `/usr/lib/systemd/system/mikagami-witness.service` | Witness（Witness 構成の第 3 のホストだけで使う） |
| `/etc/mikagami/mikagami.toml`、`witness.toml` | `%config(noreplace)`、mode 0600。注釈だけの placeholder |
| `/usr/share/licenses/mikagami/` | `LICENSE`（Apache-2.0）、`THIRD_PARTY_LICENSES.md`、`third-party/`（組み込みの第三者クレートのライセンス文） |
| `/usr/share/doc/mikagami/` | README、`docs/`、`examples/`（`contrib/examples/*.toml`） |

依存：`/usr/sbin/arping`（iputils）、`/usr/bin/curl`（check-http）、systemd、glibc。

GCE の route handoff や fencing の helper（`mikagami-gce-fence`、feature `j25-gce-fence`）はこの RPM に含まれない。使う構成では別に導入する（[`gce-fencing.md`](gce-fencing.md)）。

## パッケージ管理の安全の規則

1. **unit を起動、停止、再起動、enable しない。** install と upgrade は preset を適用せず（`%systemd_post` を使わない）、upgrade で try-restart をしない（`%systemd_postun_with_restart` を使わない）。scriptlet が呼ぶ systemctl は `daemon-reload` と、完全な削除の時の `disable`（パッケージ自身の unit だけ、`--now` なし）だけである。VIP、経路、fencing には一切触れない。
2. **HA が動いている間は install、upgrade、downgrade、削除を拒否する。** `mikagami.service` か `mikagami-witness.service` が `inactive`／`failed` 以外（`active`、`activating`、`deactivating`、`reloading` など）か、job が待っているか、`mikagami|mkg daemon run`／`witness run` のプロセスがある時、scriptlet が非 0 で終わり、rpm はパッケージをそのままに残す。systemd に状態を問えない時も拒否する（fail closed）。動いている HA daemon のバイナリを差し替えない・消さないのは v0.2 / v0.3 の installer と同じ規則（EX-09）である。systemd が動いていない環境（chroot、image のビルド）では unit が動いていることはないので、プロセスの検査だけを行う。
   この検査には限界がある：(a) 検査から rpm のファイルの置換・削除までの間に unit を起動した場合は検出できない（パッケージ操作の間は HA の unit を起動しない）。(b) systemd 管理外のプロセスは、コマンドラインに `mikagami daemon run`／`mikagami witness run`（または `mkg`）を含むものだけを検出する。別名の実行ファイルや argv[0] を書き換えたプロセスは検出しない。(c) 読めない `/proc` の項目は飛ばす。(d) `two-node takeover`、`resource`、`recover` などの短時間の操作は対象外。パッケージ操作の前に、運用者が HA を止めたことを `systemctl status` で確かめるのが前提である。
3. **HA の状態を作らない、変えない、消さない。** `/var/lib/mikagami/`（ノードの state、2 ノードの記録 `two-node-state.json` と `two-node-operator/`、route の intent、fencing の印）、`/var/lib/mikagami-witness/`（Witness の state と journal）、`/run/mikagami/` は `%files` に無く、どの scriptlet も触れない。設定で別の path にした場合も同じ。削除の後も残る。
4. **設定は `%config(noreplace)`。** 編集した設定は upgrade で残り、新しい placeholder は `.rpmnew` に書かれる。初回の install の前から同じ path にあった設定（手作業の導入の設定）も置き換えず、placeholder を `.rpmnew` に書く。削除では、編集した設定は rpm の規則で `mikagami.toml.rpmsave` に改名されて残る（再 install の後に戻す）。
5. **placeholder では HA は起動しない。** placeholder は鍵を 1 つも持たないので、`daemon run`、`two-node`、`witness` の各 command は `missing field cluster` で拒否する。`status` は `config.loaded: no` と報告する。

## 導入

```sh
dnf install ./mikagami-0.8.0-1.el9.x86_64.rpm      # el10 では .el10 の RPM
```

1. 設定を置く（mode 0600、root）。例は `/usr/share/doc/mikagami/examples/`。Witness 構成は `node-a.toml`／`node-b.toml`／`witness.toml`、2 ノード構成は `two-node-*.toml`。手順は [`deployment.md`](deployment.md) と [`TWO_NODE_ARCHITECTURE.md`](../TWO_NODE_ARCHITECTURE.md)。
2. 運用者が自分で起動する。パッケージは起動しない。
   ```sh
   systemctl enable --now mikagami            # ノード
   systemctl enable --now mikagami-witness    # Witness のホストのみ。先に mikagami witness init
   ```

手動の制御面（`mkg resource ...`）の node agent を SSH 経由で使う場合、制御の設定の `[agent] binary` の既定は `/usr/local/bin/mikagami` なので、RPM で導入したノードでは `binary = "/usr/bin/mikagami"` を書き、sudoers の command も `/usr/bin/mikagami agent` にする。

既に手作業で `/usr/local/bin/mikagami` と `/etc/systemd/system/mikagami.service` を導入したホストでは、`/etc/systemd/system/` の unit がパッケージの unit より優先され、`/usr/local/bin/mikagami` を使い続ける。パッケージの unit を使うには、HA を止めた後に運用者が `/etc` の unit を退避する。パッケージはそれらに触れない。

## 更新

[`deployment.md`](deployment.md) の「アップグレード」と同じく、互換性の約束はない（rolling upgrade は未対応）。

1. クラスタの全ホストで HA を止める（`systemctl stop mikagami`、Witness では `systemctl stop mikagami-witness`）。止めないと upgrade は拒否される。
2. `dnf upgrade ./mikagami-0.8.0-N...rpm`。
3. `.rpmnew` があれば差分を確かめる。
4. 運用者が Witness → node-b → node-a の順に起動する。

## 削除

1. HA を止める（止めないと削除は拒否される）。
2. `dnf remove mikagami`。パッケージの unit の enable は外される（`/etc/systemd/system/` にある運用者の unit や mask には触れない）。
3. `/var/lib/mikagami*` と `.rpmsave` の設定は残る。不要なら運用者が自分で消す。**Witness の state を消すことは、文書にしたクラスタ全体の復旧と一緒にだけ行う**（[`deployment.md`](deployment.md)「Witnessの状態の取り扱い」）。
