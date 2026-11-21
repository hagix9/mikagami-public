# Mikagami RPM（Rocky Linux 9 / 10）

`mikagami.spec` は Mikagami（Witness 構成と Witness なし 2 ノード構成）を RPM `mikagami-0.8.0` にする。運用の手順は [`docs/rpm.md`](../../docs/rpm.md) にある。

## ファイル

| ファイル | 内容 |
|---|---|
| `mikagami.spec` | spec。安全の規則は先頭の注釈にある |
| `build.sh` | `sources`（ソースと vendor の tarball）と `rpm`（`rpmbuild -ba`。Linux のみ） |
| `mikagami.toml`、`witness.toml` | `/etc/mikagami/` に置く placeholder（注釈のみ。そのままでは全ての読み手が拒否する） |
| `tests/test_rpm_scriptlets.sh` | spec の scriptlet を偽の systemctl で実行する試験（rpm も root も不要。`cargo test --test rpm_packaging` から実行） |
| `tests/rpm-lifecycle-test.sh` | 使い捨ての Rocky 9 / 10 のホストで root として実行する install / upgrade / erase の試験 |

systemd の unit は `contrib/systemd/` のものを `%prep` で複製し、バイナリの path（`/usr/local/bin/mikagami` → `/usr/bin/mikagami`）だけを置き換える。

## ビルド

```sh
# どのホストでも（macOS を含む）。DIR は外付けの作業 volume に置く
packaging/rpm/build.sh sources --out DIR [--rev REV]
# Rocky 9 / 10 のビルド用ホストで（rpm-build、systemd-rpm-macros、gcc）
packaging/rpm/build.sh rpm --out DIR [--release N] [--system-rust]
```

- 既定では PATH の `cargo` が `rust-toolchain.toml` の固定版（1.98.0）であることを `%build` で確かめる。`--system-rust` は distribution の `cargo`／`rust`（1.85 以上）でビルドし、固定版を強制しない。
- el9 と el10 は別々にビルドする（el10 でビルドしたバイナリは glibc 2.39 を要し、el9 の glibc 2.34 では動かない）。
- `--release N` は lifecycle 試験の upgrade のために 2 つの release を作るのに使う。

## ライセンスと版

- ライセンス：Apache-2.0（`LICENSE`、`Cargo.toml` の `license`、spec の `License:`）。RPM は `LICENSE`、`THIRD_PARTY_LICENSES.md` と、バイナリに組み込む第三者クレートのライセンス文（build の時に `third-party-licenses.py` が vendor から集める。無いクレートがあれば build は失敗する）を `/usr/share/licenses/mikagami/` に入れる。
- 版は 0.8.0 に揃えた（`Cargo.toml`、`--version`、RPM の Version、`build.sh`、試験）。`tests/rpm_packaging.rs` が一致を確かめる。
- `URL:` は公式サイト（https://mikagami.fulltrust.co.jp）。`%changelog` の連絡先は返信を受けない宛先（`noreply@example.invalid`）。

## 検証の記録

| 日付 | 環境 | 内容 | 結果 |
|---|---|---|---|
| 2026-11-20 | macOS（開発機） | `cargo test --locked`（全体）、`cargo fmt --check`、`tests/rpm_packaging.rs`、`tests/test_rpm_scriptlets.sh` 279 checks | PASS |
| 2026-11-20 | Rocky Linux 10.2 aarch64（使い捨てのビルド用 VM、HA クラスタではない）、rpm-build 4.19.1.1、Rust 1.98.0、dnf 4.20 | 0.7.0 の表記の RPM：`build.sh rpm --release 1` と `--release 2`（`%check` を含む）、`tests/rpm-lifecycle-test.sh`、`dnf install`／`upgrade`／`remove`（active の unit の下では拒否） | PASS、lifecycle 90 checks・0 failures。ビルド先のホームの path はバイナリに 0 件、release 1 と 2 のバイナリは同一 |
| 2026-11-21 | 同上（0.8.0、Apache-2.0） | `build.sh rpm --release 1` と `--release 2`（`%check` を含む）、RPM・SRPM の内容の検査、`tests/rpm-lifecycle-test.sh` | PASS（`License: Apache-2.0`、`LICENSE` は公式の原文、第三者のライセンス文 54 クレート、`mikagami`／`mkg --version` は 0.8.0、ビルド先のホームの path は 0 件、release 1 と 2 のバイナリは同一）、lifecycle 103 checks・0 failures（既存の 90 項目＋ライセンス・版・同梱物の 13 項目） |

未検証：Rocky Linux 9（el9 のビルドと導入。環境が無い）、x86_64、`--system-rust` でのビルド。el10 の RPM は `GLIBC_2.39` を要するので el9 には入らない（el9 は el9 でビルドする）。
