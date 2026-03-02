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

type ruleRepository struct {
	pool *pgxpool.Pool
}

func NewRuleRepository(pool *pgxpool.Pool) repository.RuleRepository {
	return &ruleRepository{pool: pool}
}

var _ repository.RuleRepository = (*ruleRepository)(nil)

const ruleColumns = `
	id,
	name,
	owner_id,
	mode,
	ingress_node_id,
	ingress_port,
	egress_node_id,
	lb_group_id,
	hop_chain_id,
	target_host,
	target_port,
	status,
	sync_status,
	instance_info,
	np_tls,
	np_mode,
	np_min,
	np_max,
	np_rate,
	np_notcp,
	np_noudp,
	np_log,
	created_at,
	updated_at
`

func (r *ruleRepository) FindByID(ctx context.Context, id uuid.UUID) (*model.ForwardingRule, error) {
	query := `SELECT ` + ruleColumns + ` FROM forwarding_rules WHERE id = $1`
	rule, err := scanForwardingRule(r.pool.QueryRow(ctx, query, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return rule, nil
}

func (r *ruleRepository) FindByOwner(ctx context.Context, ownerID uuid.UUID, page repository.Pagination) ([]*model.ForwardingRule, error) {
	limit, offset := normalizePagination(page)
	query := `
		SELECT ` + ruleColumns + `
		FROM forwarding_rules
		WHERE owner_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3
	`
	rows, err := r.pool.Query(ctx, query, ownerID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]*model.ForwardingRule, 0, limit)
	for rows.Next() {
		item, err := scanForwardingRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}

func (r *ruleRepository) Create(ctx context.Context, rule *model.ForwardingRule) error {
	if rule.ID == uuid.Nil {
		rule.ID = uuid.New()
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now().UTC()
	}
	if rule.UpdatedAt.IsZero() {
		rule.UpdatedAt = rule.CreatedAt
	}

	instanceInfo, err := encodeJSONMap(rule.InstanceInfo)
	if err != nil {
		return err
	}

	npTLS := intPtrToInt16Ptr(rule.NpParams.NpTLS)
	query := `
		INSERT INTO forwarding_rules (
			id, name, owner_id, mode,
			ingress_node_id, ingress_port, egress_node_id,
			lb_group_id, hop_chain_id,
			target_host, target_port,
			status, sync_status, instance_info,
			np_tls, np_mode, np_min, np_max,
			np_rate, np_notcp, np_noudp, np_log,
			created_at, updated_at
		)
		VALUES (
			$1, $2, $3, $4,
			$5, $6, $7,
			$8, $9,
			$10, $11,
			$12, $13, $14,
			$15, $16, $17, $18,
			$19, $20, $21, $22,
			$23, $24
		)
	`

	_, err = r.pool.Exec(
		ctx,
		query,
		rule.ID,
		rule.Name,
		rule.OwnerID,
		rule.Mode,
		rule.IngressNodeID,
		rule.IngressPort,
		rule.EgressNodeID,
		rule.LBGroupID,
		rule.HopChainID,
		rule.TargetHost,
		rule.TargetPort,
		rule.Status,
		rule.SyncStatus,
		instanceInfo,
		npTLS,
		rule.NpParams.NpMode,
		rule.NpParams.NpMin,
		rule.NpParams.NpMax,
		rule.NpParams.NpRate,
		rule.NpParams.NpNoTCP,
		rule.NpParams.NpNoUDP,
		rule.NpParams.NpLog,
		rule.CreatedAt,
		rule.UpdatedAt,
	)
	return err
}

func (r *ruleRepository) Update(ctx context.Context, rule *model.ForwardingRule) error {
	rule.UpdatedAt = time.Now().UTC()
	instanceInfo, err := encodeJSONMap(rule.InstanceInfo)
	if err != nil {
		return err
	}

	npTLS := intPtrToInt16Ptr(rule.NpParams.NpTLS)
	query := `
		UPDATE forwarding_rules
		SET name = $2,
			owner_id = $3,
			mode = $4,
			ingress_node_id = $5,
			ingress_port = $6,
			egress_node_id = $7,
			lb_group_id = $8,
			hop_chain_id = $9,
			target_host = $10,
			target_port = $11,
			status = $12,
			sync_status = $13,
			instance_info = $14,
			np_tls = $15,
			np_mode = $16,
			np_min = $17,
			np_max = $18,
			np_rate = $19,
			np_notcp = $20,
			np_noudp = $21,
			np_log = $22,
			updated_at = $23
		WHERE id = $1
	`

	tag, err := r.pool.Exec(
		ctx,
		query,
		rule.ID,
		rule.Name,
		rule.OwnerID,
		rule.Mode,
		rule.IngressNodeID,
		rule.IngressPort,
		rule.EgressNodeID,
		rule.LBGroupID,
		rule.HopChainID,
		rule.TargetHost,
		rule.TargetPort,
		rule.Status,
		rule.SyncStatus,
		instanceInfo,
		npTLS,
		rule.NpParams.NpMode,
		rule.NpParams.NpMin,
		rule.NpParams.NpMax,
		rule.NpParams.NpRate,
		rule.NpParams.NpNoTCP,
		rule.NpParams.NpNoUDP,
		rule.NpParams.NpLog,
		rule.UpdatedAt,
	)
	if err != nil {
		return err
	}
	return ensureAffected(tag)
}

func (r *ruleRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	query := `UPDATE forwarding_rules SET status = $2, updated_at = NOW() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, status)
	if err != nil {
		return err
	}
	return ensureAffected(tag)
}

func (r *ruleRepository) UpdateSyncStatus(ctx context.Context, id uuid.UUID, syncStatus string) error {
	query := `UPDATE forwarding_rules SET sync_status = $2, updated_at = NOW() WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id, syncStatus)
	if err != nil {
		return err
	}
	return ensureAffected(tag)
}

func (r *ruleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM forwarding_rules WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return err
	}
	return ensureAffected(tag)
}

func (r *ruleRepository) BatchDelete(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	query := `DELETE FROM forwarding_rules WHERE id = ANY($1)`
	_, err := r.pool.Exec(ctx, query, ids)
	return err
}

func (r *ruleRepository) List(ctx context.Context, filter repository.RuleListFilter) ([]*model.ForwardingRule, error) {
	limit, offset := normalizePagination(filter.Pagination)

	args := make([]any, 0, 8)
	conditions := make([]string, 0, 4)

	if filter.OwnerID != nil {
		args = append(args, *filter.OwnerID)
		conditions = append(conditions, fmt.Sprintf("owner_id = $%d", len(args)))
	}
	if filter.NodeID != nil {
		args = append(args, *filter.NodeID)
		conditions = append(conditions, fmt.Sprintf("ingress_node_id = $%d", len(args)))
	}
	if filter.Mode != nil {
		args = append(args, *filter.Mode)
		conditions = append(conditions, fmt.Sprintf("mode = $%d", len(args)))
	}
	if filter.Status != nil {
		args = append(args, *filter.Status)
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(args)))
	}
	if filter.SyncStatus != nil {
		args = append(args, *filter.SyncStatus)
		conditions = append(conditions, fmt.Sprintf("sync_status = $%d", len(args)))
	}

	var builder strings.Builder
	builder.WriteString("SELECT ")
	builder.WriteString(ruleColumns)
	builder.WriteString(" FROM forwarding_rules")

	if len(conditions) > 0 {
		builder.WriteString(" WHERE ")
		builder.WriteString(strings.Join(conditions, " AND "))
	}

	args = append(args, limit, offset)
	_, _ = fmt.Fprintf(&builder, " ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := r.pool.Query(ctx, builder.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rules := make([]*model.ForwardingRule, 0, limit)
	for rows.Next() {
		item, err := scanForwardingRule(rows)
		if err != nil {
			return nil, err
		}
		rules = append(rules, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}

func scanForwardingRule(src scanTarget) (*model.ForwardingRule, error) {
	rule := &model.ForwardingRule{}
	var instanceInfoRaw []byte
	var npTLS *int16
	var npMode *string
	var npMin *int
	var npMax *int
	var npRate *int
	var npNoTCP *bool
	var npNoUDP *bool
	var npLog *string

	err := src.Scan(
		&rule.ID,
		&rule.Name,
		&rule.OwnerID,
		&rule.Mode,
		&rule.IngressNodeID,
		&rule.IngressPort,
		&rule.EgressNodeID,
		&rule.LBGroupID,
		&rule.HopChainID,
		&rule.TargetHost,
		&rule.TargetPort,
		&rule.Status,
		&rule.SyncStatus,
		&instanceInfoRaw,
		&npTLS,
		&npMode,
		&npMin,
		&npMax,
		&npRate,
		&npNoTCP,
		&npNoUDP,
		&npLog,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	rule.InstanceInfo, err = decodeJSONMap(instanceInfoRaw)
	if err != nil {
		return nil, err
	}

	rule.NpParams = model.NpParams{
		NpTLS:   int16PtrToIntPtr(npTLS),
		NpMode:  npMode,
		NpMin:   npMin,
		NpMax:   npMax,
		NpRate:  npRate,
		NpNoTCP: npNoTCP,
		NpNoUDP: npNoUDP,
		NpLog:   npLog,
	}

	return rule, nil
}
