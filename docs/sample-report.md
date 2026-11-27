# SafeRotate audit report

**Ledger integrity: verified.** 26 entries, hash chain intact, last hash `7bc08212d674e289ec6e8922471580d553e3593f418e85691dec006b7422ec21`.

Secret values are never recorded; only keyed fingerprints (HMAC-SHA256).

## rot-20261127T212751Z: rotated, old credential revoked

| # | Time (UTC) | Step | Evidence |
|---|---|---|---|
| 1 | 2026-11-27 21:27:51 | plan | env="production", from_role="app_blue", old_fingerprint="hmac-sha256:bb9a0a7aa915218d", target="db/app", to_role="app_green" |
| 2 | 2026-11-27 21:27:51 | approved | approved=true, env="production" |
| 3 | 2026-11-27 21:27:51 | create_new | fingerprint="hmac-sha256:528b1d8a7f103492", role="app_green" |
| 4 | 2026-11-27 21:27:51 | propagate | role="app_green", store="file" |
| 5 | 2026-11-27 21:28:05 | verify | checks=8, max_error_rate=0.01, pass=true, quiet_window="10s", reason="old credential unused for 10s and error rate 0.00%" |
| 6 | 2026-11-27 21:28:05 | revoke_old | method="NOLOGIN", role="app_blue" |
| 7 | 2026-11-27 21:28:05 | done | result="rotated" |

## rot-20261127T212816Z: rotated, old credential revoked

| # | Time (UTC) | Step | Evidence |
|---|---|---|---|
| 8 | 2026-11-27 21:28:16 | plan | env="production", from_role="app_green", old_fingerprint="hmac-sha256:528b1d8a7f103492", target="db/app", to_role="app_blue" |
| 9 | 2026-11-27 21:28:16 | approved | approved=true, env="production" |
| 10 | 2026-11-27 21:28:16 | create_new | fingerprint="hmac-sha256:d6f4e342eaa55348", role="app_blue" |
| 11 | 2026-11-27 21:28:16 | propagate | role="app_blue", store="file" |
| 12 | 2026-11-27 21:28:31 | verify | checks=8, max_error_rate=0.01, pass=true, quiet_window="10s", reason="old credential unused for 10s and error rate 0.00%" |
| 13 | 2026-11-27 21:28:31 | revoke_old | method="NOLOGIN", role="app_green" |
| 14 | 2026-11-27 21:28:31 | done | result="rotated" |

## rot-20261127T212839Z: rolled back, nothing revoked

| # | Time (UTC) | Step | Evidence |
|---|---|---|---|
| 15 | 2026-11-27 21:28:39 | plan | env="production", from_role="app_blue", old_fingerprint="hmac-sha256:d6f4e342eaa55348", target="db/app", to_role="app_green" |
| 16 | 2026-11-27 21:28:39 | approved | approved=true, env="production" |
| 17 | 2026-11-27 21:28:39 | create_new | fingerprint="hmac-sha256:f7c99146157e4721", role="app_green" |
| 18 | 2026-11-27 21:28:39 | propagate | role="app_green", store="file" |
| 19 | 2026-11-27 21:29:05 | verify | checks=14, max_error_rate=0.01, pass=false, quiet_window="10s", reason="old credential still in use after 25s by: app-stale" |
| 20 | 2026-11-27 21:29:05 | rollback | disabled_role="app_green", reason="old credential still in use after 25s by: app-stale", restored_role="app_blue" |

## rot-20261127T212913Z: rolled back, nothing revoked

| # | Time (UTC) | Step | Evidence |
|---|---|---|---|
| 21 | 2026-11-27 21:29:13 | plan | env="production", from_role="app_blue", old_fingerprint="hmac-sha256:d6f4e342eaa55348", target="db/app", to_role="app_green" |
| 22 | 2026-11-27 21:29:13 | approved | approved=true, env="production" |
| 23 | 2026-11-27 21:29:13 | create_new | fingerprint="hmac-sha256:6f67add67c4db7d3", role="app_green" |
| 24 | 2026-11-27 21:29:13 | propagate | role="app_green", store="file" |
| 25 | 2026-11-27 21:29:23 | verify | checks=6, max_error_rate=0.01, pass=false, quiet_window="30s", reason="error rate 2.09% is above the 1.00% threshold" |
| 26 | 2026-11-27 21:29:23 | rollback | disabled_role="app_green", reason="error rate 2.09% is above the 1.00% threshold", restored_role="app_blue" |

