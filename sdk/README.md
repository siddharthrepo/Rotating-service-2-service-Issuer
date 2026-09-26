# s2s — Go SDK

Client library for the rotating service-to-service token issuer.

A **separate Go module** from the issuer, deliberately: importing this must not
drag a web framework, a database driver, or a metrics library into your service.
Dependencies are the standard library plus `golang.org/x/sync`.

```bash
go get github.com/siddharthrepo/Rotating-service-2-service-Issuer/sdk
```

---

## Calling another service

There are two ways, and neither is wrong. Pick by what you are calling.

### Option A — `client.For()`

```go
client, err := s2s.New(s2s.Config{
    IssuerURL:    "http://s2s-issuer.internal",
    ClientID:     os.Getenv("S2S_CLIENT_ID"),
    ClientSecret: os.Getenv("S2S_CLIENT_SECRET"),
})
defer client.Close()

billing := client.For("billing-api")        // an ordinary *http.Client
resp, err := billing.Get("http://billing-api.internal/invoices/42")
```

`For()` returns a standard `*http.Client` whose `Transport` attaches the token
on every request. Existing code that accepts an `*http.Client` works untouched.

This is the same shape as `golang.org/x/oauth2`'s `Config.Client()` — if you
have used that, this is the pattern you already know.

### Option B — `client.Token()`

```go
token, err := client.Token(ctx, "billing-api")
req.Header.Set("Authorization", "Bearer "+token)
resp, err := http.DefaultClient.Do(req)
```

No transport, nothing happening out of sight. You hold the token and attach it
yourself.

### Choosing

| | `For()` | `Token()` |
|---|---|---|
| attaches the header | automatic | you do it |
| **recovers from force-rotate** | **yes** — 401 → refresh → retry | you write it |
| works with libraries taking `*http.Client` | yes | no |
| readable without knowing `http.RoundTripper` | less so | yes |
| gRPC, Kafka, queue messages | no | **yes** |

**The deciding row is force-rotate recovery.** When an operator rotates a
credential, the token a service is holding dies immediately. `For()` notices the
401, refreshes, and replays the request — the call succeeds and nothing is
redeployed. With `Token()` that call fails, and the service recovers only at its
next scheduled refresh, up to `rotate_after` later.

You can close that gap by hand — `client.Refresh()` exists for exactly this —
but it is code at every call site rather than once in the SDK. See
`examples/manual-token/` for the two written side by side.

Use `Token()` when there is no `RoundTripper` to hook (gRPC metadata, message
headers) or when you would rather read four obvious lines than trace through
`net/http`. Use `For()` for plain HTTP, where the retry is free.

---

## Protecting your service

```go
v, err := s2s.NewValidator(s2s.Config{ /* this service's own credentials */ })

mux.Handle("/invoices", v.RequireScope("billing:read")(handler))
mux.Handle("/health",   handler) // unprotected

func handler(w http.ResponseWriter, r *http.Request) {
    caller, _ := s2s.CallerFrom(r.Context())  // "orders-api", verified
    scopes, _ := s2s.ScopesFrom(r.Context())
}
```

`Middleware` and `RequireScope` are plain `func(http.Handler) http.Handler`, so
they work with `net/http`, chi, gorilla, and anything else speaking the standard
interface. For Gin or gRPC, call `v.Validate(ctx, token)` directly — the same
code path the middleware uses.

Whatever you wrap it in, keep the `WWW-Authenticate: Bearer realm="s2s"` header
on rejections. That marker is how a *calling* SDK tells an s2s failure apart
from your application's own 401, and it is what makes force-rotate recovery
work. `Middleware` sets it for you.

---

## Configuration

| Field | Default | Notes |
|---|---|---|
| `IssuerURL` | — | required |
| `ClientID` / `ClientSecret` | — | required; this service's own, used against the **issuer only** |
| `Timeout` | 5s | bounds one issuer call |
| `RefreshJitter` | 0.1 | ±10%. Without it, pods deployed together refresh in the same millisecond, every time |
| `ValidationCacheTTL` | **0** | see below |
| `DegradedWindow` | 30s | how long to serve last-known-good verdicts when the issuer is unreachable |
| `OnError` | nil | background refresh failures; wire it to your logger |

**`ValidationCacheTTL` defaults to 0 on purpose.** With no client-side cache,
revocation is genuinely instant — there is no local copy for the issuer to fail
to invalidate. Whatever you set here is exactly how stale your organisation's
revoke button becomes. Set it only after measuring that you need to.

---

## What runs that you did not write

**Caller side.** One goroutine per target, waking at `rotate_after` with jitter
and fetching a replacement. It starts after the first token (the issuer supplies
the cadence, so the client cannot know it sooner) and stops on `Close()`.
`singleflight` collapses concurrent fetches into one issuance.

**Target side.** `singleflight` keyed on the token — 100 simultaneous requests
carrying the same token produce **one** introspect call, not 100. This is the
most important performance property on this side.

**Nothing is fetched eagerly.** `New()` and `For()` do no I/O; the first token
is issued on the first real request. Your service starts even when the issuer is
down, and only the calls that need a token fail.

---

## Failure behaviour

| situation | behaviour |
|---|---|
| Issuer unreachable, token seen before | served from the degraded window; `OnError` fires |
| Issuer unreachable, token never seen | fails closed, `503` |
| Refresh failing | the current token stays usable through its overlap window; retries back off; the request path never blocks |
| Token force-rotated | `For()` recovers transparently; `Token()` users call `Refresh()` |
| `Close()` | every goroutine stops — verified by test |

---

## Credentials

`ClientID` / `ClientSecret` authenticate to the **issuer only** and are never
sent to another service. Put them in one Kubernetes Secret mounted by every pod
— all pods share one identity, which is why tokens are issued per grant rather
than per pod.

---

## Examples

| | |
|---|---|
| `./example` | the full lifecycle in one file: issuance, reuse, scope denial, force-rotate recovery, revocation |
| `../examples/` | two real services (`orders-api`, `billing-api`) talking through the issuer; `./demo.sh` drives them |
| `../examples/manual-token/` | `For()` and `Token()` performing the same call, side by side |
