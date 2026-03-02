package jobs

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

type nodeStatusUpdater interface {
	UpdateStatus(ctx context.Context, agentID, status string) error
}

type nodeHeartbeatPinger interface {
	PingAgent(ctx context.Context, agentID string, timeout time.Duration) error
}

type NodeJob struct {
	pool        *pgxpool.Pool
	nodeService nodeStatusUpdater
	hub         nodeHeartbeatPinger
	logger      *zap.Logger
}

func NewNodeJob(
	pool *pgxpool.Pool,
	hub nodeHeartbeatPinger,
	nodeService nodeStatusUpdater,
	logger *zap.Logger,
) *NodeJob {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &NodeJob{
		pool:        pool,
		nodeService: nodeService,
		hub:         hub,
		logger:      logger,
	}
}

func (j *NodeJob) CheckHeartbeats() {
	if j == nil || j.pool == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	rows, err := j.pool.Query(
		ctx,
		`SELECT id
		   FROM node_agents
		  WHERE status = 'online'
		    AND last_seen_at IS NOT NULL
		    AND last_seen_at < NOW() - INTERVAL '90 seconds'`,
	)
	if err != nil {
		j.logger.Warn("query stale online nodes failed", zap.Error(err))
		return
	}
	defer rows.Close()

	offlineNodes := make([]uuid.UUID, 0, 8)
	var firstErr error

	for rows.Next() {
		var nodeID uuid.UUID
		if err := rows.Scan(&nodeID); err != nil {
			j.logger.Warn("scan stale node failed", zap.Error(err))
			continue
		}

		if j.hub != nil {
			probeCtx, probeCancel := context.WithTimeout(ctx, time.Second)
			pingErr := j.hub.PingAgent(probeCtx, nodeID.String(), time.Second)
			probeCancel()
			if pingErr == nil {
				continue
			}
		}

		if j.nodeService != nil {
			if err := j.nodeService.UpdateStatus(ctx, nodeID.String(), "offline"); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				j.logger.Warn("mark stale node offline failed",
					zap.String("node_id", nodeID.String()),
					zap.Error(err),
				)
				continue
			}
		} else {
			if _, err := j.pool.Exec(
				ctx,
				`UPDATE node_agents
				    SET status = 'offline',
				        last_seen_at = NOW()
				  WHERE id = $1`,
				nodeID,
			); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				j.logger.Warn("update stale node status failed",
					zap.String("node_id", nodeID.String()),
					zap.Error(err),
				)
				continue
			}
		}

		offlineNodes = append(offlineNodes, nodeID)
	}

	if err := rows.Err(); err != nil {
		j.logger.Warn("iterate stale nodes failed", zap.Error(err))
		return
	}

	if len(offlineNodes) > 0 {
		j.logger.Info("heartbeat job marked nodes offline",
			zap.Int("offline_count", len(offlineNodes)),
			zap.Strings("node_ids", uuidListToStrings(offlineNodes)),
		)
	}

	if firstErr != nil && !errors.Is(firstErr, pgx.ErrNoRows) {
		j.logger.Warn("heartbeat job finished with partial errors", zap.Error(firstErr))
	}
}
