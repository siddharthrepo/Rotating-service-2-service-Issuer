package mysql

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/siddharthrepo/Rotating-service-2-service-Issuer/pkg/structs"
)

type GraphRepo struct{ db *sqlx.DB }

func NewGraphRepo(db *sqlx.DB) *GraphRepo { return &GraphRepo{db: db} }

// FlushStats upserts drained Redis buckets.
func (r *GraphRepo) FlushStats(ctx context.Context, buckets []structs.GrantStatBucket) error {
	if len(buckets) == 0 {
		return nil
	}
	_, err := r.db.NamedExecContext(ctx, `
		INSERT INTO grant_stats (grant_id, bucket_start, call_count, deny_count)
		VALUES (:grant_id, :bucket_start, :call_count, :deny_count)
		ON DUPLICATE KEY UPDATE
			call_count = call_count + VALUES(call_count),
			deny_count = deny_count + VALUES(deny_count)`, buckets)
	if err != nil {
		return fmt.Errorf("flush grant stats: %w", err)
	}
	return nil
}

// Nodes lists every registered service with its degree in the graph.
func (r *GraphRepo) Nodes(ctx context.Context) ([]structs.GraphNode, error) {
	out := []structs.GraphNode{}
	err := r.db.SelectContext(ctx, &out, `
		SELECT s.id, s.name, COALESCE(s.owner_team,'') AS owner_team, s.status,
		       (SELECT COUNT(*) FROM grants g WHERE g.target_service_id = s.id
		          AND g.status = 'active') AS in_degree,
		       (SELECT COUNT(*) FROM grants g WHERE g.caller_service_id = s.id
		          AND g.status = 'active') AS out_degree
		  FROM services s
		 ORDER BY s.name`)
	if err != nil {
		return nil, fmt.Errorf("graph nodes: %w", err)
	}
	return out, nil
}

// Edges lists grants with call volume over the window.
func (r *GraphRepo) Edges(ctx context.Context, since time.Time) ([]structs.GraphEdge, error) {
	type row struct {
		structs.GraphEdge
		Scopes structs.ScopeList `db:"scopes"`
	}
	rows := []row{}
	err := r.db.SelectContext(ctx, &rows, `
		SELECT g.id AS grant_id,
		       caller.name AS caller,
		       target.name AS target,
		       g.status,
		       g.scopes,
		       COALESCE(SUM(st.call_count), 0) AS calls,
		       COALESCE(SUM(st.deny_count), 0) AS denies,
		       MAX(st.bucket_start) AS last_seen
		  FROM grants g
		  JOIN services caller ON caller.id = g.caller_service_id
		  JOIN services target ON target.id = g.target_service_id
		  LEFT JOIN grant_stats st
		         ON st.grant_id = g.id AND st.bucket_start >= ?
		 GROUP BY g.id, caller.name, target.name, g.status, g.scopes
		 ORDER BY calls DESC, caller.name`, since)
	if err != nil {
		return nil, fmt.Errorf("graph edges: %w", err)
	}

	out := make([]structs.GraphEdge, 0, len(rows))
	for i := range rows {
		e := rows[i].GraphEdge
		e.Scopes = []string(rows[i].Scopes)
		if e.Scopes == nil {
			e.Scopes = []string{}
		}
		out = append(out, e)
	}
	return out, nil
}

// PurgeStats drops rollups past the retention window.
func (r *GraphRepo) PurgeStats(ctx context.Context, before time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM grant_stats WHERE bucket_start < ?`, before)
	if err != nil {
		return 0, fmt.Errorf("purge grant stats: %w", err)
	}
	return res.RowsAffected()
}
