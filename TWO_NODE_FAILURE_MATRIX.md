# Mikagami 2 ノード構成 — 故障表

「試験」欄は `src/two_node/sim/tests.rs`（sim）と `src/two_node/runtime/tests.rs`（rt）の関数名である。確認の区分は、テスト実行済み（決定的シミュレーション、またはループバックの E2E）／未確認（実機）で示す。実機の試験はまだ行っていない。

| # | 反例 | 期待される挙動 | 結果 | 試験 | 確認 |
|---|---|---|---|---|---|
| F-1 | A（Active）だけの故障（電源断） | B は dwell の後に fence し、verify の `isolated` を確認してから epoch 2 で昇格する | 期待どおり | sim `active_power_loss_is_taken_over_only_after_a_confirmed_fence`、rt `loopback_two_links_cold_start_then_fenced_takeover` | テスト実行済み／実機は未確認 |
| F-2 | B（Standby）だけの故障 | A は継続し、Active は fence しない | 期待どおり | sim `standby_failure_changes_nothing_on_the_active` | テスト実行済み |
| F-3 | 片方のセグメントだけの停止（どちらでも） | fence しない。経路の劣化を WARN | 期待どおり | sim `one_of_two_segments_down_never_fences` | テスト実行済み |
| F-4 | 両方のセグメントの停止（fencing の経路は別） | B が A を fence し、停止を確認してから昇格する | 期待どおり | sim `both_segments_down_fences_then_promotes_the_standby` | テスト実行済み |
| F-5 | 1 セグメントの停止、fencing の経路を共有 | fence が届かないので昇格しない。A が継続する | 期待どおり | sim `single_segment_down_with_shared_fence_path_never_promotes` | テスト実行済み |
| F-6 | 1 セグメントの停止、fencing の経路は別 | fence の確認の後に昇格する | 期待どおり | sim `single_segment_down_with_separate_fence_path_takes_over_after_fence` | テスト実行済み |
| F-7 | fencing なしで peer を喪失（1 / 2 セグメント） | 自動では昇格しない | 期待どおり | sim `without_fencing_a_peer_loss_is_never_taken_over_automatically` | テスト実行済み |
| F-8 | 非対称な通信断（A→B だけ、B→A だけ） | 両側で link が down になる。二重の所有は起きない | 期待どおり | sim `asymmetric_loss_takes_both_sides_down_and_stays_safe` | テスト実行済み |
| F-9 | fencing の失敗（failure を報告） | 昇格しない。試行は上限つき | 期待どおり | sim `fence_failure_timeout_and_accept_without_stop_never_promote_and_are_bounded` | テスト実行済み |
| F-10 | fencing の timeout | 同上 | 期待どおり | 同上 | テスト実行済み |
| F-11 | 受理されたが停止しない（success の報告、peer は稼働中） | verify が `not-isolated` を返す。以後は自動で fence しない | 期待どおり | 同上 | テスト実行済み |
| F-12 | ACPI のような遅い停止（90 s）と、既定の verify の窓（20 s） | 結論が出ないので昇格しない（安全側に失敗）。`verify_polls = 60` なら昇格する | 期待どおり | sim `slow_os_stop_beyond_the_verify_window_…` | テスト実行済み（Lima での実測の結果と整合） |
| F-13 | fencing の完了直後に外部の要因で再起動 | 再起動した側は Standby で始まり、新しい epoch を学ぶ。古い所有は再開しない | 期待どおり | sim `restart_right_after_the_fence_comes_back_standby_and_never_resumes` | テスト実行済み |
| F-14 | 同時の起動、同時の昇格要求（SIGUSR1 を両側に） | 昇格は 1 回だけ | 期待どおり | sim `simultaneous_start_and_simultaneous_promotion_requests_elect_one`、`contention_without_preference_…` | テスト実行済み |
| F-15 | 古い fencing の応答（別の op ID の結果） | 無視する | 期待どおり | sim `stale_fence_results_are_ignored` | テスト実行済み |
| F-16 | 前の attempt や前の process の proof | 起動時に incident を破棄する。遅れて届いた `isolated` は無視する | 期待どおり | sim `a_confirmed_proof_of_a_previous_attempt_or_process_is_never_reused` | テスト実行済み |
| F-17 | process だけの停止（OS は稼働、資源は残る） | peer は OS の段階で fence する（process の停止と OS の停止を区別する） | 期待どおり | sim `killed_mikagami_process_on_the_active_is_fenced_at_os_level` | テスト実行済み |
| F-18 | process の停止と即時の再起動 | 再起動した側は資源を解放して Standby になる。協調で再選出される | 期待どおり | sim `killed_process_restarting_quickly_returns_standby_…` | テスト実行済み |
| F-19 | service の起動の失敗 | 巻き戻して解放し、失敗を数える。peer が所有できる | 期待どおり | sim `service_start_failure_rolls_back_and_the_peer_can_own` | テスト実行済み |
| F-20 | 両側で起動に失敗する | 上限で止まる（それ以上昇格を繰り返さない） | 期待どおり | sim `start_failures_on_both_nodes_stop_at_the_failure_limit` | テスト実行済み |
| F-21 | VIP の解放の失敗 | Blocked。peer は協調では所有しない。回復すると再選出される | 期待どおり | sim `vip_release_failure_blocks_and_the_peer_never_takes_over_cooperatively` | テスト実行済み |
| F-22 | 電源断（両側）からの復帰 | 新しい epoch で 1 台が Active になる | 期待どおり | sim `both_nodes_lose_power_and_recover_with_a_new_epoch` | テスト実行済み |
| F-23 | 永続の state の破損 | cleanup-only mode。所有しない（付与だけ）。peer が故障しても引き継がない | 期待どおり | sim `corrupt_record_means_cleanup_only_and_never_ownership`、store の試験 | テスト実行済み |
| F-24 | intent の保存の失敗 | 資源に触れない | 期待どおり | sim `a_failed_intent_write_never_starts_resources` | テスト実行済み |
| F-25 | 計画停止（SIGTERM） | 解放した後、peer が即座に引き継ぐ | 期待どおり | sim `graceful_shutdown_of_the_active_hands_over` | テスト実行済み |
| F-26 | 旧 Active が引き継ぎの後に復帰 | Standby のまま、epoch を学ぶ | 期待どおり | sim `old_active_returning_after_takeover_stays_standby` | テスト実行済み |
| F-27 | grant の消失 | 昇格しない。後で解決して再選出される | 期待どおり | sim `a_lost_grant_never_promotes_and_resolves_later` | テスト実行済み |
| F-28 | announce と control の到着順の逆転 | どちらの順でも 1 台を選ぶ | 期待どおり | sim `cold_start_works_in_both_delivery_orders`、ランダム探索 | テスト実行済み |
| F-29 | 単独での起動 | 自動では昇格しない（wait_for_all） | 期待どおり | sim `a_lone_node_never_promotes_automatically_wait_for_peer` | テスト実行済み |
| F-30 | operator の attestation（peer が接続中 / 停止中、再使用） | 接続中は拒否する。停止中は昇格する。再使用は拒否する | 期待どおり | sim `operator_attestation_is_refused_while_the_peer_is_connected_and_used_once` | テスト実行済み |
| F-31 | fencing なしでの operator の fence 要求 | 拒否する | 期待どおり | sim `operator_fence_request_needs_an_independent_device` | テスト実行済み |
| F-32 | verify の嘘（前提 A-1 を破る） | 分断中は二重 Active になる（前提の外）。再接続で検出し、古い側が手放す | 前提の外として明示した | sim `lying_verify_is_an_explicit_assumption_and_contradiction_relinquishes` | テスト実行済み |
| F-33 | PSK の不一致 | link が up にならず、何も昇格しない | 期待どおり | rt `a_peer_with_the_wrong_key_never_connects_and_nothing_promotes` | テスト実行済み |
| F-34 | control lock の喪失 | 保護される副作用を止めて終了する | 期待どおり | rt `a_lost_control_lock_stops_protected_effects` | テスト実行済み |
| F-35 | 再送、順序の入れ替え、別の接続からの再生 | session の規則で拒否し、接続を閉じる | 期待どおり | wire の試験 | テスト実行済み |
| F-R | 上の故障をランダムに組み合わせる（5 つの構成 × 120 seed × 600 s 相当） | S-1〜S-6 の違反なし。故障が止めば 1 台が Active に戻る | 期待どおり | sim `randomized_fault_schedules_never_violate_safety`、`randomized_runs_make_progress_when_faults_stop` | テスト実行済み |

## 実機に依存する未確認の項目

- 実際の fence device（GCE の `mikagami-gce-fence`、IPMI など）が `MIKAGAMI_FENCE_INCIDENT` と `MIKAGAMI_FENCE_ATTEMPT` で 2 ノード構成の operation ID に正しく結びつき、OS の停止だけを `isolated` とするか（前提 A-1）。
- 実際の netlink の VIP、systemd、ARP を使った Linux での 2 台の E2E（2 つの NIC、実際のセグメントの断）。
- 電源断の時の fsync の耐久性（記録の保存）。
