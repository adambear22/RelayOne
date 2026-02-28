package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
)

type nodeRepository struct {
	pool *pgxpool.Pool
}

func NewNodeRepository(pool *pgxpool.Pool) repository.NodeRepository {
	return &nodeRepository{pool: pool}
}

var _ repository.NodeRepository = (*nodeRepository)(nil)

const nodeColumns = `
	id,
	name,
	type,
	owner_id,
	is_self_hosted,
	host,
	api_port,
	token,
	status,
	deploy_status,
	deploy_error,
	vip_level_req,
	traffic_ratio,
	port_range_min,
	port_range_max,
	arch,
	agent_version,
	sys_info,
	last_seen_at,
	install_script_expires_at,
	created_at
`

func (r *nodeRepository) FindByID(ctx context.Context, id uuid.UUID) (*model.NodeAgent, error) {
	query := `SELECT ` + nodeColumns + ` FROM node_agents WHERE id = $1`
	node, err := scanNodeAgent(r.pool.QueryRow(ctx, query, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return node, nil
}

func (r *nodeRepository) FindByOwner(ctx context.Context, ownerID uuid.UUID, page repository.Pagination) ([]*model.NodeAgent, error) {
	limit, offset := normalizePagination(page)
	query := `
		SELECT ` + nodeColumns + `
		FROM node_agents
		WHERE owner_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`

	rows, err := r.pool.Query(ctx, query, ownerID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nodes := make([]*model.NodeAgent, 0, limit)
	for rows.Next() {
		item, err := scanNodeAgent(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nodes, nil
}

func (r *nodeRepository) Create(ctx context.Context, node *model.NodeAgent) error {
	if node.ID == uuid.Nil {
		node.ID = uuid.New()
	}
	if node.CreatedAt.IsZero() {
		node.CreatedAt = time.Now().UTC()
	}

	sysInfo, err := encodeJSONMap(node.SysInfo)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO node_agents (
			id, name, type, owner_id, is_self_hosted,
			host, api_port, token, status, deploy_status,
			deploy_error, vip_level_req, traffic_ratio,
			port_range_min, port_range_max, arch, agent_version,
			sys_info, last_seen_at, install_script_expires_at, created_at
		)
		VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10,
			$11, $12, $13,
			$14, $15, $16, $17,
			$18, $19, $20, $21
		)
	`

	_, err = r.pool.Exec(
		ctx,
		query,
		node.ID,
		node.Name,
		node.Type,
		node.OwnerID,
		node.IsSelfHosted,
		node.Host,
		node.APIPort,
		node.Token,
		node.Status,
		node.DeployStatus,
		node.DeployError,
		node.VIPLevelReq,
		node.TrafficRatio,
		node.PortRangeMin,
		node.PortRangeMax,
		node.Arch,
		node.AgentVersion,
		sysInfo,
		node.LastSeenAt,
		node.InstallScriptExpiresAt,
		node.CreatedAt,
	)
	return err
}

func (r *nodeRepository) Update(ctx context.Context, node *model.NodeAgent) error {
	sysInfo, err := encodeJSONMap(node.SysInfo)
	if err != nil {
		return err
	}

	query := `
		UPDATE node_agents
		SET name = $2,
			type = $3,
			owner_id = $4,
			is_self_hosted = $5,
			host = $6,
			api_port = $7,
			token = $8,
			status = $9,
			deploy_status = $10,
			deploy_error = $11,
			vip_level_req = $12,
			traffic_ratio = $13,
			port_range_min = $14,
			port_range_max = $15,
			arch = $16,
			agent_version = $17,
			sys_info = $18,
			last_seen_at = $19,
			install_script_expires_at = $20
		WHERE id = $1
	`

	tag, err := r.pool.Exec(
		ctx,
		query,
		node.ID,
		node.Name,
		node.Type,
		node.OwnerID,
		node.IsSelfHosted,
		node.Host,
		node.APIPort,
		node.Token,
		node.Status,
		node.DeployStatus,
		node.DeployError,
		node.VIPLevelReq,
		node.TrafficRatio,
		node.PortRangeMin,
		node.PortRangeMax,
		node.Arch,
		node.AgentVersion,
		sysInfo,
		node.LastSeenAt,
		node.InstallScriptExpiresAt,
	)
	if err != nil {
		return err
	}
	return ensureAffected(tag)
}

func (r *nodeRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	query := `UPDATE node_agents SET status = $2 WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, status)
	if err != nil {
		return err
	}
	return ensureAffected(tag)
}

func (r *nodeRepository) UpdateDeployStatus(ctx context.Context, id uuid.UUID, deployStatus string, deployError *string) error {
	query := `
		UPDATE node_agents
		SET deploy_status = $2,
			deploy_error = $3
		WHERE id = $1
	`
	tag, err := r.pool.Exec(ctx, query, id, deployStatus, deployError)
	if err != nil {
		return err
	}
	return ensureAffected(tag)
}

func (r *nodeRepository) List(ctx context.Context, filter repository.NodeListFilter) ([]*model.NodeAgent, error) {
	limit, offset := normalizePagination(filter.Pagination)

	args := make([]any, 0, 8)
	conditions := make([]string, 0, 4)

	if filter.OwnerID != nil {
		args = append(args, *filter.OwnerID)
		conditions = append(conditions, fmt.Sprintf("owner_id = $%d", len(args)))
	}
	if filter.Type != nil {
		args = append(args, *filter.Type)
		conditions = append(conditions, fmt.Sprintf("type = $%d", len(args)))
	}
	if filter.Status != nil {
		args = append(args, *filter.Status)
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(args)))
	}
	if filter.DeployStatus != nil {
		args = append(args, *filter.DeployStatus)
		conditions = append(conditions, fmt.Sprintf("deploy_status = $%d", len(args)))
	}

	var builder strings.Builder
	builder.WriteString("SELECT ")
	builder.WriteString(nodeColumns)
	builder.WriteString(" FROM node_agents")

	if len(conditions) > 0 {
		builder.WriteString(" WHERE ")
		builder.WriteString(strings.Join(conditions, " AND "))
	}

	args = append(args, limit, offset)
	builder.WriteString(fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args)))

	rows, err := r.pool.Query(ctx, builder.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	nodes := make([]*model.NodeAgent, 0, limit)
	for rows.Next() {
		item, err := scanNodeAgent(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return nodes, nil
}

func (r *nodeRepository) UpdateHeartbeat(ctx context.Context, id uuid.UUID, status string, lastSeenAt time.Time) error {
	query := `
		UPDATE node_agents
		SET status = $2,
			last_seen_at = $3
		WHERE id = $1
	`

	tag, err := r.pool.Exec(ctx, query, id, status, lastSeenAt)
	if err != nil {
		return err
	}

	return ensureAffected(tag)
}

func (r *nodeRepository) UpdateRuntimeInfo(
	ctx context.Context,
	id uuid.UUID,
	version string,
	arch string,
	sysInfo map[string]interface{},
	lastSeenAt time.Time,
	status string,
) error {
	sysInfoRaw, err := encodeJSONMap(sysInfo)
	if err != nil {
		return err
	}

	query := `
		UPDATE node_agents
		SET agent_version = COALESCE(NULLIF($2, ''), agent_version),
			arch = COALESCE(NULLIF($3, ''), arch),
			sys_info = COALESCE($4::jsonb, sys_info),
			last_seen_at = $5,
			status = COALESCE(NULLIF($6, ''), status)
		WHERE id = $1
	`

	tag, err := r.pool.Exec(ctx, query, id, version, arch, sysInfoRaw, lastSeenAt, status)
	if err != nil {
		return err
	}

	return ensureAffected(tag)
}

func (r *nodeRepository) InsertDeployLog(ctx context.Context, nodeID uuid.UUID, step string, progress int, message string) error {
	query := `
		INSERT INTO node_deploy_logs (node_id, step, progress, message, created_at)
		VALUES ($1, $2, $3, $4, NOW())
	`
	_, err := r.pool.Exec(ctx, query, nodeID, step, progress, message)
	return err
}

func scanNodeAgent(src scanTarget) (*model.NodeAgent, error) {
	node := &model.NodeAgent{}
	var sysInfoRaw []byte

	err := src.Scan(
		&node.ID,
		&node.Name,
		&node.Type,
		&node.OwnerID,
		&node.IsSelfHosted,
		&node.Host,
		&node.APIPort,
		&node.Token,
		&node.Status,
		&node.DeployStatus,
		&node.DeployError,
		&node.VIPLevelReq,
		&node.TrafficRatio,
		&node.PortRangeMin,
		&node.PortRangeMax,
		&node.Arch,
		&node.AgentVersion,
		&sysInfoRaw,
		&node.LastSeenAt,
		&node.InstallScriptExpiresAt,
		&node.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	node.SysInfo, err = decodeJSONMap(sysInfoRaw)
	if err != nil {
		return nil, err
	}

	return node, nil
}
