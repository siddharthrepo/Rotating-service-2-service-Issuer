// Package test holds integration tests that run against the real MySQL and
// Redis from deploy/docker-compose.yml.
//
//	make up && go test ./test/... -v
//
// They are skipped unless S2S_TEST_MYSQL_DSN is set, so `go test ./...` stays
// green on a machine with no containers.
package test

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/constants"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/crypto"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/repository/mysql"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/repository/rediscache"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/service"
	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

type harness struct {
	db       *sqlx.DB
	rdb      *redis.Client
	registry *service.Registry
	grants   *service.Grants
	tokens   *service.Tokens
	revoke   *service.Revocation
	audit    *service.Audit
	caller   *structs.Service
	target   *structs.Service
	grant    *structs.Grant
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	dsn := os.Getenv("S2S_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set S2S_TEST_MYSQL_DSN to run integration tests (see: make up)")
	}
	redisAddr := os.Getenv("S2S_TEST_REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6381"
	}

	db, err := mysql.Open(structs.MySQL{DSN: dsn, MaxOpenConns: 25, MaxIdleConns: 25, ConnMaxLifetime: time.Minute})
	if err != nil {
		t.Fatalf("mysql: %v", err)
	}
	rdb, err := rediscache.Open(structs.Redis{Addr: redisAddr, PoolSize: 25, DialTimeout: time.Second, ReadTimeout: time.Second})
	if err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { db.Close(); rdb.Close() })

	// Cheap argon2 params: these tests exercise cache behaviour, not hashing.
	argon := structs.Argon2Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}

	var (
		serviceRepo = mysql.NewServiceRepo(db)
		grantRepo   = mysql.NewGrantRepo(db)
		auditRepo   = mysql.NewAuditRepo(db)
		tokenRepo   = mysql.NewTokenRepo(db)
		txManager   = mysql.NewTxManager(db)

		auditSvc    = service.NewAudit(auditRepo)
		registrySvc = service.NewRegistry(serviceRepo, auditSvc, argon,
			rediscache.NewServiceAuth(rdb), time.Minute)
		grantsSvc = service.NewGrants(grantRepo, registrySvc, auditSvc,
			structs.Tokens{DefaultLifetime: 45 * time.Minute, DefaultRotateAfter: 15 * time.Minute, MaxLifetime: 24 * time.Hour})
		tokenCache = rediscache.NewTokenCache(rdb)
		tokensSvc  = service.NewTokens(tokenRepo, grantsSvc, rediscache.NewCurrentTokens(rdb),
			tokenCache, txManager, auditSvc, rediscache.NewStats(rdb), time.Second)
		revokeSvc = service.NewRevocation(tokenRepo, grantRepo, rediscache.NewCurrentTokens(rdb),
			tokenCache, txManager, auditSvc, zap.NewNop())
	)
	registrySvc.SetTokenInvalidator(revokeSvc)

	h := &harness{db: db, rdb: rdb, registry: registrySvc, grants: grantsSvc,
		tokens: tokensSvc, revoke: revokeSvc, audit: auditSvc}
	h.reset(t)
	h.seed(t)
	return h
}

// reset clears every table this suite touches. Tests must not inherit state.
func (h *harness) reset(t *testing.T) {
	t.Helper()
	for _, stmt := range []string{
		"DELETE FROM grant_stats", "DELETE FROM tokens",
		"DELETE FROM grants", "DELETE FROM services", "DELETE FROM audit_log",
	} {
		if _, err := h.db.Exec(stmt); err != nil {
			t.Fatalf("reset %q: %v", stmt, err)
		}
	}
	if err := h.rdb.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("flush redis: %v", err)
	}
}

func (h *harness) seed(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	actor := structs.Actor{Type: constants.ActorUser, ID: "test"}

	callerCreds, err := h.registry.Create(ctx, structs.CreateServiceInput{Name: "caller-svc", Actor: actor})
	if err != nil {
		t.Fatalf("create caller: %v", err)
	}
	targetCreds, err := h.registry.Create(ctx, structs.CreateServiceInput{Name: "target-svc", Actor: actor})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}
	h.caller, h.target = callerCreds.Service, targetCreds.Service

	detail, err := h.grants.Create(ctx, structs.CreateGrantInput{
		CallerName: "caller-svc", TargetName: "target-svc",
		Scopes: []string{"x:read"}, Actor: actor,
	})
	if err != nil {
		t.Fatalf("create grant: %v", err)
	}
	h.grant = &detail.Grant
}

func (h *harness) issue(t *testing.T) string {
	t.Helper()
	res, err := h.tokens.Issue(context.Background(), service.IssueInput{
		Caller: h.caller, TargetName: "target-svc",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return res.Response.Token
}

func (h *harness) introspect(t *testing.T, token string) *structs.IntrospectResponse {
	t.Helper()
	res, err := h.tokens.Introspect(context.Background(), h.target, token)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	return res
}

// ─────────────────────────── BUG 1 ────────────────────────────────────

// Disabling a service must kill its LIVE tokens, not just stop it getting new
// ones. Regression: the cached record carries the endpoints' statuses as they
// were when written, so a warm cache kept a disabled service's tokens valid for
// up to a full token lifetime.
func TestDisablingServiceInvalidatesLiveTokens(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := h.issue(t)

	// Warm the cache so the stale-status path is the one under test.
	if res := h.introspect(t, token); !res.Active {
		t.Fatalf("token should start valid, got %+v", res)
	}
	if h.rdb.Exists(ctx, "tok:"+crypto.HashToken(token)).Val() != 1 {
		t.Fatal("expected the validation cache to be warm")
	}

	if err := h.registry.SetStatus(ctx, h.caller.ID, constants.ServiceDisabled,
		structs.Actor{Type: constants.ActorUser, ID: "test"}); err != nil {
		t.Fatalf("disable: %v", err)
	}

	res := h.introspect(t, token)
	if res.Active {
		t.Fatal("BUG 1: a disabled service's live token is still being accepted")
	}
	if res.Reason != constants.ReasonServiceDisabled {
		t.Errorf("reason = %q, want %q (an operator needs to see why)",
			res.Reason, constants.ReasonServiceDisabled)
	}
}

// Disabling the TARGET must also invalidate, not just the caller.
func TestDisablingTargetInvalidatesLiveTokens(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := h.issue(t)
	h.introspect(t, token)

	if err := h.registry.SetStatus(ctx, h.target.ID, constants.ServiceDisabled,
		structs.Actor{Type: constants.ActorUser, ID: "test"}); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if res := h.introspect(t, token); res.Active {
		t.Fatal("disabling the target left its tokens valid")
	}
}

// Disabling must also clear the grant's current-token key.
//
// Otherwise re-enabling within rotate_after hands the caller back the same
// tombstoned token: the SDK 401s, refreshes, gets the identical dead token,
// and loops until the key expires.
func TestDisableThenReenableIssuesAFreshToken(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	actor := structs.Actor{Type: constants.ActorUser, ID: "test"}

	first := h.issue(t)
	h.introspect(t, first)

	if err := h.registry.SetStatus(ctx, h.caller.ID, constants.ServiceDisabled, actor); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if h.rdb.Exists(ctx, fmt.Sprintf("grant:cur:%d", h.grant.ID)).Val() != 0 {
		t.Fatal("grant:cur survived the disable; a re-enable would reissue a dead token")
	}

	if err := h.registry.SetStatus(ctx, h.caller.ID, constants.ServiceActive, actor); err != nil {
		t.Fatalf("re-enable: %v", err)
	}

	second := h.issue(t)
	if second == first {
		t.Fatal("re-enabling handed back the tombstoned token")
	}
	if res := h.introspect(t, second); !res.Active {
		t.Fatalf("the reissued token is not usable: %+v", res)
	}
}

// ─────────────────────────── BUG 2 ────────────────────────────────────

// blockingTokenRepo wraps the real repo and lets a test stop a ByHash call
// midway, holding open the exact window revocation has to survive: the reader
// has loaded a valid row from MySQL but has not yet written it to the cache.
type blockingTokenRepo struct {
	*mysql.TokenRepo
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingTokenRepo) ByHash(ctx context.Context, hash string) (*structs.TokenDetail, error) {
	out, err := b.TokenRepo.ByHash(ctx, hash)
	// Only the first read blocks; later ones run normally.
	b.once.Do(func() {
		close(b.entered)
		<-b.release
	})
	return out, err
}

// The revocation race, driven through Introspect rather than the cache API.
//
// A reader misses the cache and loads a valid row from MySQL. While it is still
// in flight, a revocation commits and writes its tombstone. The reader then
// finishes and tries to cache what it saw.
//
// With an unconditional Set the reader overwrites the tombstone and the token
// is served as valid for the rest of its TTL. With SetIfAbsent the write loses,
// the reader re-reads the winning entry, and the revocation stands.
//
// This exercises service.Tokens.lookup(), which is where the bug actually
// lives -- testing the cache primitive alone passes either way.
func TestRevocationBeatsInFlightCacheFill(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := h.issue(t)
	hash := crypto.HashToken(token)

	// A Tokens service whose repository can be paused mid-read.
	blocking := &blockingTokenRepo{
		TokenRepo: mysql.NewTokenRepo(h.db),
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	slowTokens := service.NewTokens(blocking, h.grants,
		rediscache.NewCurrentTokens(h.rdb), rediscache.NewTokenCache(h.rdb),
		mysql.NewTxManager(h.db), h.audit, rediscache.NewStats(h.rdb), time.Second)

	// Cold cache, so the read really does reach MySQL.
	if err := h.rdb.Del(ctx, "tok:"+hash).Err(); err != nil {
		t.Fatalf("clear cache: %v", err)
	}

	type result struct {
		res *structs.IntrospectResponse
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := slowTokens.Introspect(ctx, h.target, token)
		done <- result{res, err}
	}()

	<-blocking.entered // the reader now holds a pre-revocation view

	if _, err := h.revoke.RevokeGrant(ctx, h.grant.ID,
		structs.Actor{Type: constants.ActorUser, ID: "test"}, "in-flight race"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	close(blocking.release) // let the stale reader finish and try to cache
	got := <-done
	if got.err != nil {
		t.Fatalf("introspect: %v", got.err)
	}

	// The in-flight reader itself must not report active either: it can see
	// the tombstone that landed while it was blocked.
	if got.res.Active {
		t.Error("BUG 2: the in-flight reader reported active after the revoke committed")
	}

	// And nothing afterwards may see a resurrected token.
	if res := h.introspect(t, token); res.Active {
		t.Fatal("BUG 2: an in-flight cache fill resurrected a revoked token")
	}
}

// The same race under real concurrency.
//
// The guarantee being asserted is the one the product claims: once RevokeGrant
// has returned, no introspection that STARTS afterwards may report active. A
// call already in flight when the revoke commits is allowed to answer from what
// it legitimately saw; a call begun after is not.
func TestConcurrentIntrospectDuringRevoke(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := h.issue(t)

	const readers = 24
	var (
		wg           sync.WaitGroup
		revokedAt    atomic.Int64 // set once RevokeGrant returns
		resurrection atomic.Int64
		after        atomic.Int64
		stop         = make(chan struct{})
	)

	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				started := time.Now().UnixNano()
				res, err := h.tokens.Introspect(ctx, h.target, token)
				if err != nil {
					continue
				}
				cutoff := revokedAt.Load()
				if cutoff == 0 || started <= cutoff {
					continue // in flight across the revoke, or before it
				}
				after.Add(1)
				if res.Active {
					resurrection.Add(1)
				}
			}
		}()
	}

	// Deliberately do NOT warm the cache. Readers must actually reach MySQL,
	// or the race window never opens and this test proves nothing.
	time.Sleep(150 * time.Millisecond)
	if _, err := h.revoke.RevokeGrant(ctx, h.grant.ID,
		structs.Actor{Type: constants.ActorUser, ID: "test"}, "concurrent revoke"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	revokedAt.Store(time.Now().UnixNano())

	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()

	t.Logf("%d introspections began after the revoke returned", after.Load())
	if after.Load() < 100 {
		t.Fatalf("only %d post-revoke introspections; the test did not exercise the race", after.Load())
	}
	if n := resurrection.Load(); n > 0 {
		t.Fatalf("BUG 2: %d introspections started after the revoke and still reported active", n)
	}
}

// Revocation must be visible on the very next call, not after a TTL.
func TestRevocationIsImmediate(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := h.issue(t)
	h.introspect(t, token)

	start := time.Now()
	if _, err := h.revoke.RevokeGrant(ctx, h.grant.ID,
		structs.Actor{Type: constants.ActorUser, ID: "test"}, "timing"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	res := h.introspect(t, token)
	elapsed := time.Since(start)

	if res.Active {
		t.Fatal("token still active on the first call after revoke")
	}
	if res.Reason != constants.ReasonRevoked {
		t.Errorf("reason = %q, want %q", res.Reason, constants.ReasonRevoked)
	}
	t.Logf("revoke to first rejection: %v", elapsed)
}

// A tombstone must not outlive the token it describes.
func TestTombstoneExpiresWithTheToken(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	token := h.issue(t)
	h.introspect(t, token)

	if _, err := h.revoke.RevokeGrant(ctx, h.grant.ID,
		structs.Actor{Type: constants.ActorUser, ID: "test"}, "ttl check"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	ttl := h.rdb.TTL(ctx, "tok:"+crypto.HashToken(token)).Val()
	if ttl <= 0 {
		t.Fatalf("tombstone has no TTL (%v); it would linger forever", ttl)
	}
	if ttl > 45*time.Minute {
		t.Fatalf("tombstone TTL %v exceeds the token lifetime", ttl)
	}
	t.Logf("tombstone TTL %v, within the token's remaining lifetime", ttl)
}
