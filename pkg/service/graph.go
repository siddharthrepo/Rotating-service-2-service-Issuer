package service

import (
	"context"
	"time"

	"github.com/siddharth120604/rotating-s2s/pkg/constants"
	"github.com/siddharth120604/rotating-s2s/pkg/structs"
)

type graphRepo interface {
	FlushStats(ctx context.Context, buckets []structs.GrantStatBucket) error
	Nodes(ctx context.Context) ([]structs.GraphNode, error)
	Edges(ctx context.Context, since time.Time) ([]structs.GraphEdge, error)
	PurgeStats(ctx context.Context, before time.Time) (int64, error)
}

// StatsRecorder counts validations for the dependency graph.
type StatsRecorder interface {
	Record(ctx context.Context, grantID uint64, allowed bool)
	Drain(ctx context.Context) ([]structs.GrantStatBucket, error)
}

// Graph builds the service dependency map.
type Graph struct {
	repo  graphRepo
	stats StatsRecorder
	now   func() time.Time
}

func NewGraph(repo graphRepo, stats StatsRecorder) *Graph {
	return &Graph{repo: repo, stats: stats, now: time.Now}
}

func (g *Graph) Build(ctx context.Context) (*structs.Graph, error) {
	nodes, err := g.repo.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	edges, err := g.repo.Edges(ctx, g.now().Add(-constants.GraphWindow))
	if err != nil {
		return nil, err
	}
	return &structs.Graph{
		Nodes:      nodes,
		Edges:      edges,
		WindowSecs: int(constants.GraphWindow.Seconds()),
	}, nil
}

// Flush drains Redis counters into MySQL.
func (g *Graph) Flush(ctx context.Context) (int, error) {
	buckets, err := g.stats.Drain(ctx)
	if err != nil {
		return 0, err
	}
	if len(buckets) == 0 {
		return 0, nil
	}
	if err := g.repo.FlushStats(ctx, buckets); err != nil {
		return 0, err
	}
	return len(buckets), nil
}
