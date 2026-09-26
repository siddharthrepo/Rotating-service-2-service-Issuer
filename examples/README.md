# Two services talking through the issuer

A worked example of what this project is for.

```
  curl ──▶ orders-api ════════▶ billing-api
           (public edge)   ▲    (protected)
                           │
                    the s2s hop
                           │
                        ISSUER
```

- **billing-api** — a *target*. Every `/invoices/` route requires a valid token
  minted for billing-api carrying `billing:read`. It holds no secret belonging
  to orders-api.
- **orders-api** — a *caller*. Public `/orders/{id}` fetches invoice data from
  billing-api over an authenticated call. It holds no secret belonging to
  billing-api either.

Neither service shares anything with the other. Each has one credential, for
the issuer alone.

## Run it

```bash
./demo.sh          # needs the issuer running on :8080, plus jq
```

The script registers both services, grants `orders → billing`, starts them, and
walks ten steps: an unauthenticated call being rejected, a successful s2s call,
scope denial, force-rotate recovery, and revocation.

## The integration, in full

**Caller** (`orders-api/main.go`) — no token variable, no refresh timer, no
retry logic:

```go
client, _ := s2s.New(s2s.Config{IssuerURL: ..., ClientID: ..., ClientSecret: ...})
billing := client.For(billingService)      // an *http.Client
resp, err := billing.Get(billingURL + "/invoices/" + id)
```

**Target** (`billing-api/main.go`):

```go
v, _ := s2s.NewValidator(s2s.Config{ /* billing's own credentials */ })
mux.Handle("/invoices/", v.RequireScope("billing:read")(handler))

caller, _ := s2s.CallerFrom(r.Context())   // "orders-api", verified
```

## Identity is not an address

`orders-api` takes two separate settings:

| | |
|---|---|
| `BILLING_URL` | where billing-api listens — `http://127.0.0.1:19001` |
| `BILLING_SERVICE` | its registered identity — `billing-api` |

The token is minted for the **identity**; the request goes to the **address**.
Moving a service to a new host changes the URL and nothing about its auth.

## What each step proves

| Step | Shows |
|---|---|
| 4 | An unauthenticated call is rejected — there is no shared secret to leak or guess |
| 5 | `served_to` is the caller identity *verified by the issuer*, not self-reported |
| 6 | Scopes narrow a single grant per route: `billing:read` granted, `billing:write` refused |
| 7–8 | Force-rotate kills the live token; the next call recovers via 401 → refresh → retry, with no restart or redeploy |
| 9–10 | Revoking ends access in one click, on both sides, with no deploy |

Step 8 is the one worth watching. An operator killed the credential mid-flight,
and neither service was touched.
