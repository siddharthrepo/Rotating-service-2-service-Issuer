#!/usr/bin/env bash
# Registers two services with the issuer, runs them, and walks the lifecycle:
# a normal s2s call, scope denial, force-rotate recovery, and revocation.
set -euo pipefail

ISSUER=${ISSUER:-http://localhost:8080}
ADMIN=${S2S_SERVER_ADMIN_API_KEY:-dev-admin-key-change-me}

# Used only to tidy up afterwards; the demo itself talks to the HTTP API.
DB_CONTAINER=${DB_CONTAINER:-rotating-s2s-mysql}
DB_USER=${DB_USER:-s2s}
DB_PASS=${DB_PASS:-s2spw}
DB_NAME=${DB_NAME:-s2s}
KEEP=${KEEP:-0}
RUN=$(mktemp -d)
PIDS=()
# Remove everything this run created, so repeated demos do not accumulate
# services in the database. Done over SQL because the API has no delete
# endpoint yet -- a real gap, not a deliberate omission.
cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  if [ -n "${ORDERS:-}" ] && command -v docker >/dev/null 2>&1; then
    docker exec -i "$DB_CONTAINER" mysql -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" 2>/dev/null <<SQL || true
DELETE t FROM tokens t
  JOIN grants g ON g.id = t.grant_id
  JOIN services s ON s.id = g.caller_service_id
 WHERE s.name IN ('$ORDERS', '$BILLING');
DELETE gs FROM grant_stats gs
  JOIN grants g ON g.id = gs.grant_id
  JOIN services s ON s.id = g.caller_service_id
 WHERE s.name IN ('$ORDERS', '$BILLING');
DELETE g FROM grants g
  JOIN services s ON s.id = g.caller_service_id OR s.id = g.target_service_id
 WHERE s.name IN ('$ORDERS', '$BILLING');
DELETE FROM services WHERE name IN ('$ORDERS', '$BILLING');
SQL
  fi
  rm -rf "$RUN"
}
trap cleanup EXIT

# Free the demo ports in case a previous run left something behind.
for port in 19001 19002; do
  pid=$(ss -ltnp 2>/dev/null | grep ":$port " | grep -oP 'pid=\K[0-9]+' | head -1 || true)
  [ -n "${pid:-}" ] && kill -9 "$pid" 2>/dev/null || true
done

say()  { printf "\n\033[1;36m== %s\033[0m\n" "$*"; }
note() { printf "   %s\n" "$*"; }

api() { curl -s -X POST "$ISSUER$1" -H "Authorization: Bearer $ADMIN" \
             -H 'Content-Type: application/json' -d "$2"; }

SUFFIX=$(date +%H%M%S)
ORDERS="orders-api-$SUFFIX"
BILLING="billing-api-$SUFFIX"

say "1. Register both services with the issuer"
api /v1/services "{\"name\":\"$ORDERS\",\"owner_team\":\"commerce\"}"  > "$RUN/orders.json"
api /v1/services "{\"name\":\"$BILLING\",\"owner_team\":\"finance\"}" > "$RUN/billing.json"
jq -r '"   \(.name)  client_id=\(.client_id)"' "$RUN/orders.json" "$RUN/billing.json"
note "each got its OWN credential -- they share no secret with each other"

say "2. Grant $ORDERS the right to call $BILLING"
GRANT=$(api /v1/grants "{\"caller\":\"$ORDERS\",\"target\":\"$BILLING\",
        \"scopes\":[\"billing:read\"],\"lifetime\":\"10m\",\"rotate_after\":\"2m\"}")
echo "$GRANT" | jq -r '"   grant \(.id): \(.caller) -> \(.target)  scopes=\(.scopes)  overlap=\(.overlap)"'
GRANT_ID=$(echo "$GRANT" | jq -r .id)
note "no grant, no token -- registering a service grants nothing by itself"

say "3. Start both services"
# Build first: `go run` forks a child that survives killing the parent.
go build -o "$RUN/billing-api" ./billing-api
go build -o "$RUN/orders-api"  ./orders-api

S2S_ISSUER_URL=$ISSUER \
S2S_CLIENT_ID=$(jq -r .client_id "$RUN/billing.json") \
S2S_CLIENT_SECRET=$(jq -r .client_secret "$RUN/billing.json") \
  "$RUN/billing-api" > "$RUN/billing.log" 2>&1 &
PIDS+=($!)

S2S_ISSUER_URL=$ISSUER \
S2S_CLIENT_ID=$(jq -r .client_id "$RUN/orders.json") \
S2S_CLIENT_SECRET=$(jq -r .client_secret "$RUN/orders.json") \
BILLING_URL=http://127.0.0.1:19001 \
BILLING_SERVICE=$BILLING \
  "$RUN/orders-api" > "$RUN/orders.log" 2>&1 &
PIDS+=($!)

for i in $(seq 1 60); do
  curl -sf http://127.0.0.1:19001/healthz >/dev/null 2>&1 &&
  curl -sf http://127.0.0.1:19002/healthz >/dev/null 2>&1 && break
  sleep 1
done
note "billing-api on :19001   orders-api on :19002"

say "4. Call billing-api DIRECTLY without a token"
curl -s -o "$RUN/direct" -w "   HTTP %{http_code}  " http://127.0.0.1:19001/invoices/inv-1001
head -c 80 "$RUN/direct"; echo
note "the target rejects anything unauthenticated -- no shared secret to guess"

say "5. Call orders-api, which calls billing-api over s2s"
curl -s http://127.0.0.1:19002/orders/ord-1 | jq .
note "served_to is the VERIFIED caller identity, from the issuer -- not self-reported"

say "6. Scope enforcement: orders has billing:read, not billing:write"
curl -s http://127.0.0.1:19002/refund-check | jq .
note "one grant, narrowed per route by scope"

say "7. Operator force-rotates the token (simulating a suspected leak)"
curl -s -X POST "$ISSUER/v1/grants/$GRANT_ID/rotate" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"reason":"demo: credential suspected leaked"}' | jq -r '"   revoked \(.tokens_revoked) token(s), new jti \(.new_token_jti)"'
note "orders-api is now holding a dead token and does not know it"

say "8. Same call again -- the SDK recovers with no restart"
curl -s http://127.0.0.1:19002/orders/ord-1 | jq -c '{order: .order.id, invoice: .invoice.id, served_to: .invoice.served_to}'
note "401 -> refresh -> retry, invisibly. Nothing was redeployed."

say "9. Operator revokes the grant entirely"
curl -s -X POST "$ISSUER/v1/grants/$GRANT_ID/revoke" \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"reason":"demo: access withdrawn"}' | jq -r '"   \(.status), \(.tokens_revoked) token(s) killed"'

say "10. orders-api can no longer reach billing-api"
curl -s http://127.0.0.1:19002/orders/ord-1 | jq -c '{order: .order.id, billing_status, billing_body}'
note "access ended in one click -- no deploy on either side"

if [ "$KEEP" = "1" ]; then
  note "KEEP=1 -- leaving $ORDERS and $BILLING in the database"
  ORDERS=""   # disables the cleanup below
fi

say "Service logs"
echo "--- billing-api ---"; tail -4 "$RUN/billing.log" | sed 's/^/   /'
echo "--- orders-api  ---"; tail -4 "$RUN/orders.log"  | sed 's/^/   /'
