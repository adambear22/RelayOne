package service

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
)

var (
	ErrPortExhausted       = errors.New("port exhausted")
	ErrPortPoolUnavailable = errors.New("port pool unavailable")
	ErrPortOutOfRange      = errors.New("port out of range")
)

type PortPool struct {
	mu     sync.Mutex
	nodeID string
	min    int
	max    int
	used   map[int]struct{}
}

func NewPortPool(nodeID string, min, max int, existingPorts []int) *PortPool {
	pool := &PortPool{
		nodeID: nodeID,
		min:    min,
		max:    max,
		used:   make(map[int]struct{}),
	}

	for _, port := range existingPorts {
		if port < min || port > max {
			continue
		}
		pool.used[port] = struct{}{}
	}

	return pool
}

func (p *PortPool) Allocate() (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for port := p.min; port <= p.max; port++ {
		if _, exists := p.used[port]; exists {
			continue
		}

		p.used[port] = struct{}{}
		p.warnIfHighUsageLocked()
		return port, nil
	}

	return 0, ErrPortExhausted
}

func (p *PortPool) Release(port int) {
	p.mu.Lock()
	defer p.mu.Unlock()

	delete(p.used, port)
}

func (p *PortPool) reserve(port int) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if port < p.min || port > p.max {
		return fmt.Errorf("%w: %d not in [%d,%d]", ErrPortOutOfRange, port, p.min, p.max)
	}
	if _, exists := p.used[port]; exists {
		return ErrPortExhausted
	}

	p.used[port] = struct{}{}
	p.warnIfHighUsageLocked()
	return nil
}

func (p *PortPool) warnIfHighUsageLocked() {
	total := p.max - p.min + 1
	if total <= 0 {
		return
	}

	usage := float64(len(p.used)) / float64(total)
	if usage <= 0.8 {
		return
	}

	zap.L().Warn(
		"port pool usage exceeds 80%",
		zap.String("node_id", p.nodeID),
		zap.Int("used", len(p.used)),
		zap.Int("capacity", total),
		zap.Float64("usage_ratio", usage),
	)
}

type PortAwareRuleRepository struct {
	inner       repository.RuleRepository
	nodeService *NodeService
}

func NewPortAwareRuleRepository(
	inner repository.RuleRepository,
	nodeService *NodeService,
) repository.RuleRepository {
	if inner == nil {
		return nil
	}
	if nodeService == nil {
		return inner
	}

	return &PortAwareRuleRepository{
		inner:       inner,
		nodeService: nodeService,
	}
}

var _ repository.RuleRepository = (*PortAwareRuleRepository)(nil)

func (r *PortAwareRuleRepository) FindByID(ctx context.Context, id uuid.UUID) (*model.ForwardingRule, error) {
	return r.inner.FindByID(ctx, id)
}

func (r *PortAwareRuleRepository) FindByOwner(ctx context.Context, ownerID uuid.UUID, page repository.Pagination) ([]*model.ForwardingRule, error) {
	return r.inner.FindByOwner(ctx, ownerID, page)
}

func (r *PortAwareRuleRepository) Create(ctx context.Context, rule *model.ForwardingRule) error {
	if rule == nil {
		return errors.New("rule is nil")
	}

	trackedPort := 0
	portTracked := false

	if rule.IngressPort > 0 {
		err := r.nodeService.reservePortForNode(ctx, rule.IngressNodeID, rule.IngressPort)
		switch {
		case err == nil:
			trackedPort = rule.IngressPort
			portTracked = true
		case errors.Is(err, ErrPortPoolUnavailable):
			// no pool range configured for this node, keep caller-provided port
		default:
			return err
		}
	} else {
		port, err := r.nodeService.allocatePortForNode(ctx, rule.IngressNodeID)
		if err != nil {
			return err
		}
		rule.IngressPort = port
		trackedPort = port
		portTracked = true
	}

	if err := r.inner.Create(ctx, rule); err != nil {
		if portTracked {
			r.nodeService.releasePortForNode(rule.IngressNodeID, trackedPort)
		}
		return err
	}

	return nil
}

func (r *PortAwareRuleRepository) Update(ctx context.Context, rule *model.ForwardingRule) error {
	return r.inner.Update(ctx, rule)
}

func (r *PortAwareRuleRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	return r.inner.UpdateStatus(ctx, id, status)
}

func (r *PortAwareRuleRepository) UpdateSyncStatus(ctx context.Context, id uuid.UUID, syncStatus string) error {
	return r.inner.UpdateSyncStatus(ctx, id, syncStatus)
}

func (r *PortAwareRuleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	rule, err := r.inner.FindByID(ctx, id)
	if err != nil {
		return err
	}

	if err := r.inner.Delete(ctx, id); err != nil {
		return err
	}

	r.nodeService.releasePortForNode(rule.IngressNodeID, rule.IngressPort)
	return nil
}

func (r *PortAwareRuleRepository) BatchDelete(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}

	released := make([]struct {
		NodeID uuid.UUID
		Port   int
	}, 0, len(ids))

	for _, id := range ids {
		rule, err := r.inner.FindByID(ctx, id)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				continue
			}
			return err
		}
		released = append(released, struct {
			NodeID uuid.UUID
			Port   int
		}{
			NodeID: rule.IngressNodeID,
			Port:   rule.IngressPort,
		})
	}

	if err := r.inner.BatchDelete(ctx, ids); err != nil {
		return err
	}

	for _, item := range released {
		r.nodeService.releasePortForNode(item.NodeID, item.Port)
	}

	return nil
}

func (r *PortAwareRuleRepository) List(ctx context.Context, filter repository.RuleListFilter) ([]*model.ForwardingRule, error) {
	return r.inner.List(ctx, filter)
}
