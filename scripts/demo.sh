#!/usr/bin/env bash
# Runs one demo scenario against the docker-compose stack (make demo-up first).
#   rotate  rotate under load; passes only with zero failed requests
#   stale   an app that never reloads keeps the old role; rotation must roll back
#   chaos   error rate rises during verify; rotation must roll back
set -euo pipefail
cd "$(dirname "$0")/.."
COMPOSE="docker compose -f deploy/docker-compose.yml"
CLI="$COMPOSE run --rm -T saferotate"
stats() { curl -fsS http://localhost:8090/stats; }

scenario=${1:-rotate}
case $scenario in
  rotate) args=(--quiet 10s --max-wait 60s) ;;
  stale)  $COMPOSE --profile stale up -d --wait app-stale; args=(--quiet 10s --max-wait 25s) ;;
  chaos)  args=(--quiet 30s --max-wait 60s) ;;
  *) echo "unknown scenario $scenario"; exit 2 ;;
esac

echo "== who uses the secret now"
$CLI discover
sleep 3
curl -fsS -X POST http://localhost:8090/reset
echo "== rotating under load ($scenario)"
if [ "$scenario" = chaos ]; then
  ( sleep 8; for a in app1 app2; do $COMPOSE exec -T $a wget -qO- "http://localhost:8080/chaos?fail_percent=20"; done ) &
fi
set +e
$CLI rotate --approve "${args[@]}"
code=$?
set -e
wait
if [ "$scenario" = chaos ]; then
  for a in app1 app2; do $COMPOSE exec -T $a wget -qO- "http://localhost:8080/chaos?fail_percent=0" >/dev/null; done
fi
sleep 3
s=$(stats)
echo "== load generator during rotation: $s"
echo "== who uses the secret after"
$CLI discover
[ "$scenario" = stale ] && $COMPOSE --profile stale stop app-stale >/dev/null

case $scenario in
  rotate)
    [ $code -eq 0 ] || { echo "FAIL: rotation exited $code"; exit 1; }
    echo "$s" | grep -q '"failed":0' || { echo "FAIL: requests failed during rotation"; exit 1; }
    echo "PASS: rotated with zero failed requests" ;;
  stale|chaos)
    [ $code -eq 3 ] || { echo "FAIL: expected a rollback (exit 3), got $code"; exit 1; }
    echo "PASS: rotation rolled back, old credential kept" ;;
esac
