# SafeRotate

A platform that knows who uses every secret, so it can rotate a leaked one in minutes without breaking production. It can also prove the fix to auditors.

## Why

Most secret managers can create a new credential, but revoking the old one is a blind, time-based guess. That guess broke production at Cloudflare R2 (March 2025: the old key was deleted while production still used it) and at Polar (June 2026: a routine DB credential rotation dropped the production database).

SafeRotate revokes the old credential **only after it has proof**: the old credential has had zero use for a quiet window, and error rates stayed normal. Otherwise it rolls back by itself. Every step is written to a hash-chained evidence ledger.

## How a rotation works (Postgres)

Postgres has one password per role, so the app logs in through one of two roles, `app_blue` and `app_green`, which both inherit privileges from the group role `app`.

1. **Plan**: read which role the store points to (say `app_blue`); the target is `app_green`. Policy: production needs `--approve`.
2. **Create**: set a fresh random password on `app_green` and allow login.
3. **Propagate**: write the new credential to the secret store. Apps reload it and switch pools.
4. **Verify** (the revoke gate): poll `pg_stat_activity` for sessions on `app_blue` and Prometheus for the error ratio. Pass when `app_blue` has had zero sessions for `--quiet` and errors are below `--max-error-rate`.
5. **Revoke**: set `app_blue` to `NOLOGIN` (deactivate first; the next rotation overwrites its password).
6. **Rollback** if verify fails or times out (`--max-wait`): restore the old credential in the store, re-enable `app_blue`, disable `app_green`. Exit code 3.

Secret values are held only in memory; the ledger stores keyed fingerprints (HMAC-SHA256).

## Run the demo

Needs Docker with Compose v2.

```sh
make demo-up        # Postgres, two demo apps, a 50 req/s load generator, Prometheus
make demo-rotate    # rotate under load; passes only with zero failed requests
make demo-stale     # an app that never reloads blocks the revoke -> rollback
make demo-chaos     # 20% errors injected during verify -> rollback
make demo-report    # audit report from the evidence ledger
make demo-down
```

Example output of `make demo-rotate`:

```
plan: db/app from app_blue to app_green (production)
create: new password set on app_green
propagate: store now points to app_green
verify: 2 session(s) on app_blue [app1 app2], error rate 0.00%
verify: 0 session(s) on app_blue [], error rate 0.00%
...
verify: pass (old credential unused for 10s and error rate 0.00%)
revoke: app_blue set to NOLOGIN
== load generator during rotation: {"failed":0,"ok":880}
PASS: rotated with zero failed requests
```

See [docs/sample-report.md](docs/sample-report.md) for the audit report.

## CLI

```
saferotate discover   who is using each role right now (from pg_stat_activity)
saferotate plan       what a rotation would do (dry run)
saferotate rotate     create, propagate, verify, revoke (or roll back)
saferotate report     Markdown audit report; fails if the hash chain is broken
```

SafeRotate connects as its own least-privilege role (`CREATEROLE` plus `ADMIN OPTION` on just the two app roles), not as a superuser. See `deploy/postgres/init.sql`.

## Layout

```
cmd/saferotate/        CLI
cmd/demoapp/           demo service that reloads its DB credential from a file
cmd/loadgen/           load generator that counts failed requests
internal/postgres/     Postgres connector: role changes, sessions per role
internal/store/        secret store (JSON file on a shared volume)
internal/health/       Prometheus error-ratio check
internal/verify/       the revoke gate
internal/rotation/     the rotation steps, policy and rollback
internal/evidence/     hash-chained ledger and report
deploy/                docker-compose demo
scripts/demo.sh        demo scenarios (also run in CI)
```

## Status and roadmap

The MVP covers the Postgres path end to end in the local demo. Next, tracked as GitHub issues:

- AWS IAM access key connector (two-key pattern, last-used + CloudTrail) and AWS Secrets Manager store
- Kubernetes Secret store with pod reload
- Temporal workflow so a crashed rotation resumes where it stopped
- OPA policies (freeze windows, approvers) in place of the built-in production-needs-approval rule
- Slack/Teams approvals, leak-alert webhooks, web dashboard, SOC 2 / DORA control mapping
