package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
	"nodepass-hub/internal/sse"
	cryptoutil "nodepass-hub/pkg/crypto"
	"nodepass-hub/templates"
)

const (
	nodeInstallScriptTTL  = time.Hour
	nodeListDefaultPage   = 1
	nodeListDefaultSize   = 20
	nodeListMaxPageSize   = 200
	nodeDefaultArch       = "amd64"
	nodeDefaultType       = "egress"
	nodeDefaultStatus     = "pending"
	nodeDefaultDeploy     = "pending"
	nodeDefaultAgentVer   = "latest"
	nodeDefaultTrafficRat = 1.0
)

var (
	ErrNodeNotFound     = errors.New("node not found")
	ErrInvalidNodeID    = errors.New("invalid node id")
	ErrInstallForbidden = errors.New("install script forbidden")
)

type NodeServiceConfig struct {
	HubWSURL        string
	AgentVersion    string
	HMACSecret      string
	DeployProgress  string
	DownloadBaseURL string
}

type CreateNodeRequest struct {
	Name         string  `json:"name"`
	Type         string  `json:"type"`
	Host         string  `json:"host"`
	APIPort      int     `json:"api_port"`
	Arch         string  `json:"arch"`
	PortRangeMin *int    `json:"port_range_min"`
	PortRangeMax *int    `json:"port_range_max"`
	IsSelfHosted bool    `json:"is_self_hosted"`
	VIPLevelReq  int     `json:"vip_level_req"`
	TrafficRatio float64 `json:"traffic_ratio"`
}

type UpdateNodeRequest struct {
	Name         *string  `json:"name"`
	Type         *string  `json:"type"`
	Host         *string  `json:"host"`
	APIPort      *int     `json:"api_port"`
	Arch         *string  `json:"arch"`
	PortRangeMin *int     `json:"port_range_min"`
	PortRangeMax *int     `json:"port_range_max"`
	IsSelfHosted *bool    `json:"is_self_hosted"`
	VIPLevelReq  *int     `json:"vip_level_req"`
	TrafficRatio *float64 `json:"traffic_ratio"`
}

type NodeListFilter struct {
	OwnerID      *string
	Type         *string
	Status       *string
	DeployStatus *string
}

type TCPTestResult struct {
	Reachable bool          `json:"reachable"`
	Latency   time.Duration `json:"latency"`
	Error     string        `json:"error,omitempty"`
}

type DeployProgressPayload struct {
	AgentID  string `json:"agent_id"`
	Step     string `json:"step"`
	Progress int    `json:"progress"`
	Message  string `json:"message"`
}

type NodeService struct {
	nodeRepo  repository.NodeRepository
	auditRepo repository.AuditRepository
	sseHub    *sse.SSEHub
	pool      *pgxpool.Pool
	cfg       NodeServiceConfig
	logger    *zap.Logger

	installTokens sync.Map
	portPools     sync.Map
}

type cachedInstallToken struct {
	Token     string
	ExpiresAt time.Time
}

type installScriptTemplateData struct {
	AgentID           string
	AgentToken        string
	AgentAuthToken    string
	HubWSURL          string
	AgentVersion      string
	Arch              string
	DownloadBaseURL   string
	DeployProgressURL string
}

func NewNodeService(
	nodeRepo repository.NodeRepository,
	auditRepo repository.AuditRepository,
	sseHub *sse.SSEHub,
	pool *pgxpool.Pool,
	cfg NodeServiceConfig,
	logger *zap.Logger,
) *NodeService {
	if logger == nil {
		logger = zap.NewNop()
	}

	svc := &NodeService{
		nodeRepo:  nodeRepo,
		auditRepo: auditRepo,
		sseHub:    sseHub,
		pool:      pool,
		cfg:       cfg,
		logger:    logger,
	}

	svc.initializePortPools(context.Background())

	return svc
}

func (s *NodeService) Create(ctx context.Context, ownerID string, req CreateNodeRequest) (*model.NodeAgent, error) {
	ownerUUID, err := uuid.Parse(ownerID)
	if err != nil {
		return nil, ErrInvalidUserID
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Host) == "" || req.APIPort <= 0 {
		return nil, ErrInvalidUserInput
	}

	now := time.Now().UTC()
	nodeID := uuid.New()
	rawToken, err := generateHexToken(32)
	if err != nil {
		return nil, err
	}

	hashedToken, err := bcrypt.GenerateFromPassword([]byte(rawToken), 10)
	if err != nil {
		return nil, err
	}

	nodeType := strings.TrimSpace(req.Type)
	if nodeType == "" {
		nodeType = nodeDefaultType
	}

	arch := strings.TrimSpace(req.Arch)
	if arch == "" {
		arch = nodeDefaultArch
	}

	trafficRatio := req.TrafficRatio
	if trafficRatio <= 0 {
		trafficRatio = nodeDefaultTrafficRat
	}

	installExpireAt := now.Add(nodeInstallScriptTTL)
	node := &model.NodeAgent{
		ID:                     nodeID,
		Name:                   strings.TrimSpace(req.Name),
		Type:                   nodeType,
		OwnerID:                &ownerUUID,
		IsSelfHosted:           req.IsSelfHosted,
		Host:                   strings.TrimSpace(req.Host),
		APIPort:                req.APIPort,
		Token:                  string(hashedToken),
		Status:                 nodeDefaultStatus,
		DeployStatus:           nodeDefaultDeploy,
		VIPLevelReq:            req.VIPLevelReq,
		TrafficRatio:           trafficRatio,
		PortRangeMin:           req.PortRangeMin,
		PortRangeMax:           req.PortRangeMax,
		Arch:                   arch,
		InstallScriptExpiresAt: &installExpireAt,
		CreatedAt:              now,
	}

	if err := s.nodeRepo.Create(ctx, node); err != nil {
		return nil, err
	}

	if err := s.syncPortPoolForNode(ctx, node); err != nil {
		s.logger.Warn("sync node port pool failed after create",
			zap.String("node_id", node.ID.String()),
			zap.Error(err),
		)
	}

	s.installTokens.Store(nodeID.String(), cachedInstallToken{
		Token:     rawToken,
		ExpiresAt: installExpireAt,
	})

	s.writeAudit(ctx, ownerID, "node.create", node.ID.String(), nil, map[string]interface{}{
		"id":            node.ID.String(),
		"name":          node.Name,
		"type":          node.Type,
		"status":        node.Status,
		"deploy_status": node.DeployStatus,
	})

	response := cloneNode(node)
	response.Token = rawToken
	return response, nil
}

func (s *NodeService) GenerateInstallScript(ctx context.Context, nodeID string, installToken string) (string, error) {
	nodeUUID, err := uuid.Parse(nodeID)
	if err != nil {
		return "", ErrInvalidNodeID
	}

	node, err := s.nodeRepo.FindByID(ctx, nodeUUID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", ErrNodeNotFound
		}
		return "", err
	}

	now := time.Now().UTC()
	if node.InstallScriptExpiresAt == nil || !node.InstallScriptExpiresAt.After(now) {
		return "", ErrInstallForbidden
	}

	cachedTokenAny, ok := s.installTokens.Load(nodeID)
	if !ok {
		return "", ErrInstallForbidden
	}
	cachedToken, ok := cachedTokenAny.(cachedInstallToken)
	if !ok || cachedToken.Token == "" || !cachedToken.ExpiresAt.After(now) {
		s.installTokens.Delete(nodeID)
		return "", ErrInstallForbidden
	}

	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(installToken)), []byte(cachedToken.Token)) != 1 {
		return "", ErrInstallForbidden
	}

	downloadBaseURL, err := s.resolveDownloadBaseURL(ctx)
	if err != nil {
		return "", err
	}

	hubWSURL := strings.TrimSpace(s.cfg.HubWSURL)
	agentVersion := strings.TrimSpace(s.cfg.AgentVersion)
	if agentVersion == "" {
		agentVersion = nodeDefaultAgentVer
	}

	tmplData := installScriptTemplateData{
		AgentID:           node.ID.String(),
		AgentToken:        cachedToken.Token,
		AgentAuthToken:    cryptoutil.GenerateAgentHMACToken(node.ID.String(), s.cfg.HMACSecret),
		HubWSURL:          hubWSURL,
		AgentVersion:      agentVersion,
		Arch:              node.Arch,
		DownloadBaseURL:   downloadBaseURL,
		DeployProgressURL: s.resolveDeployProgressURL(),
	}

	tpl, err := template.New("install.sh").Parse(templates.InstallScriptTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, tmplData); err != nil {
		return "", err
	}

	scriptBody := buf.String()
	scriptChecksum := computeScriptChecksum(scriptBody, cachedToken.Token)
	finalScript := injectScriptChecksum(scriptBody, scriptChecksum)

	s.installTokens.Delete(nodeID)

	return finalScript, nil
}

func (s *NodeService) HandleDeployProgress(ctx context.Context, agentID string, payload DeployProgressPayload) error {
	nodeID, err := uuid.Parse(agentID)
	if err != nil {
		return ErrInvalidNodeID
	}

	now := time.Now().UTC()
	if _, err := s.pool.Exec(
		ctx,
		`INSERT INTO node_deploy_logs (node_id, step, progress, message, created_at) VALUES ($1, $2, $3, $4, $5)`,
		nodeID,
		strings.TrimSpace(payload.Step),
		payload.Progress,
		strings.TrimSpace(payload.Message),
		now,
	); err != nil {
		return err
	}

	node, err := s.nodeRepo.FindByID(ctx, nodeID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrNodeNotFound
		}
		return err
	}

	recipients, err := s.collectDeployEventRecipients(ctx, node)
	if err != nil {
		return err
	}

	if s.sseHub != nil && len(recipients) > 0 {
		event := sse.NewEvent(sse.EventDeployProgress, map[string]interface{}{
			"agent_id": agentID,
			"step":     strings.TrimSpace(payload.Step),
			"progress": payload.Progress,
			"message":  strings.TrimSpace(payload.Message),
			"ts":       now.Format(time.RFC3339Nano),
		})
		s.sseHub.SendToUsers(recipients, event)
	}

	return nil
}

func (s *NodeService) VerifyAgentToken(agentID, rawToken string) (bool, error) {
	nodeID, err := uuid.Parse(agentID)
	if err != nil {
		return false, ErrInvalidNodeID
	}

	node, err := s.nodeRepo.FindByID(context.Background(), nodeID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return false, ErrNodeNotFound
		}
		return false, err
	}

	if bcrypt.CompareHashAndPassword([]byte(node.Token), []byte(rawToken)) != nil {
		return false, nil
	}

	return true, nil
}

func (s *NodeService) UpdateStatus(ctx context.Context, agentID, status string) error {
	nodeID, err := uuid.Parse(agentID)
	if err != nil {
		return ErrInvalidNodeID
	}

	node, err := s.nodeRepo.FindByID(ctx, nodeID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrNodeNotFound
		}
		return err
	}

	node.Status = strings.TrimSpace(status)
	now := time.Now().UTC()
	node.LastSeenAt = &now

	if strings.EqualFold(node.Status, "online") && !strings.EqualFold(node.DeployStatus, "success") {
		node.DeployStatus = "success"
		node.InstallScriptExpiresAt = nil
		s.installTokens.Delete(node.ID.String())
	}

	if err := s.nodeRepo.Update(ctx, node); err != nil {
		return err
	}

	if s.sseHub != nil {
		event := sse.NewEvent(sse.EventNodeStatus, map[string]interface{}{
			"agent_id":      node.ID.String(),
			"status":        node.Status,
			"deploy_status": node.DeployStatus,
			"ts":            now.Format(time.RFC3339Nano),
		})
		s.sseHub.Broadcast(event)
	}

	return nil
}

func (s *NodeService) List(ctx context.Context, page, pageSize int, filter NodeListFilter) ([]*model.NodeAgent, int64, error) {
	page, pageSize = normalizeNodeListPage(page, pageSize)

	repoFilter := repository.NodeListFilter{
		Pagination: repository.Pagination{
			Limit:  int32(pageSize),
			Offset: int32((page - 1) * pageSize),
		},
	}

	if filter.OwnerID != nil {
		owner, err := uuid.Parse(strings.TrimSpace(*filter.OwnerID))
		if err != nil {
			return nil, 0, ErrInvalidUserID
		}
		repoFilter.OwnerID = &owner
	}
	if filter.Type != nil {
		t := strings.TrimSpace(*filter.Type)
		if t != "" {
			repoFilter.Type = &t
		}
	}
	if filter.Status != nil {
		st := strings.TrimSpace(*filter.Status)
		if st != "" {
			repoFilter.Status = &st
		}
	}
	if filter.DeployStatus != nil {
		ds := strings.TrimSpace(*filter.DeployStatus)
		if ds != "" {
			repoFilter.DeployStatus = &ds
		}
	}

	nodes, err := s.nodeRepo.List(ctx, repoFilter)
	if err != nil {
		return nil, 0, err
	}

	total, err := s.countNodes(ctx, repoFilter)
	if err != nil {
		return nil, 0, err
	}

	result := make([]*model.NodeAgent, 0, len(nodes))
	for _, node := range nodes {
		result = append(result, sanitizeNode(node))
	}

	return result, total, nil
}

func (s *NodeService) GetByID(ctx context.Context, id string) (*model.NodeAgent, error) {
	nodeID, err := uuid.Parse(id)
	if err != nil {
		return nil, ErrInvalidNodeID
	}

	node, err := s.nodeRepo.FindByID(ctx, nodeID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrNodeNotFound
		}
		return nil, err
	}

	return sanitizeNode(node), nil
}

func (s *NodeService) Update(ctx context.Context, nodeID string, req UpdateNodeRequest) (*model.NodeAgent, error) {
	nodeUUID, err := uuid.Parse(nodeID)
	if err != nil {
		return nil, ErrInvalidNodeID
	}

	node, err := s.nodeRepo.FindByID(ctx, nodeUUID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrNodeNotFound
		}
		return nil, err
	}

	if req.Name != nil {
		node.Name = strings.TrimSpace(*req.Name)
	}
	if req.Type != nil {
		node.Type = strings.TrimSpace(*req.Type)
	}
	if req.Host != nil {
		node.Host = strings.TrimSpace(*req.Host)
	}
	if req.APIPort != nil {
		node.APIPort = *req.APIPort
	}
	if req.Arch != nil {
		node.Arch = strings.TrimSpace(*req.Arch)
	}
	if req.PortRangeMin != nil {
		node.PortRangeMin = req.PortRangeMin
	}
	if req.PortRangeMax != nil {
		node.PortRangeMax = req.PortRangeMax
	}
	if req.IsSelfHosted != nil {
		node.IsSelfHosted = *req.IsSelfHosted
	}
	if req.VIPLevelReq != nil {
		node.VIPLevelReq = *req.VIPLevelReq
	}
	if req.TrafficRatio != nil {
		node.TrafficRatio = *req.TrafficRatio
	}

	if err := s.nodeRepo.Update(ctx, node); err != nil {
		return nil, err
	}

	if err := s.syncPortPoolForNode(ctx, node); err != nil {
		s.logger.Warn("sync node port pool failed after update",
			zap.String("node_id", node.ID.String()),
			zap.Error(err),
		)
	}

	return sanitizeNode(node), nil
}

func (s *NodeService) Delete(ctx context.Context, nodeID string) error {
	nodeUUID, err := uuid.Parse(nodeID)
	if err != nil {
		return ErrInvalidNodeID
	}

	tag, err := s.pool.Exec(ctx, `DELETE FROM node_agents WHERE id = $1`, nodeUUID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNodeNotFound
	}

	s.installTokens.Delete(nodeID)
	s.portPools.Delete(nodeUUID.String())
	return nil
}

func (s *NodeService) TestTCPConnectivity(ctx context.Context, nodeID string, targetHost string, targetPort int, timeout time.Duration) (*TCPTestResult, error) {
	if _, err := s.GetByID(ctx, nodeID); err != nil {
		return nil, err
	}

	host := strings.TrimSpace(targetHost)
	if host == "" || targetPort <= 0 || targetPort > 65535 {
		return nil, ErrInvalidUserInput
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	start := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(targetPort)))
	if err != nil {
		return &TCPTestResult{Reachable: false, Error: err.Error()}, nil
	}
	_ = conn.Close()

	return &TCPTestResult{Reachable: true, Latency: time.Since(start)}, nil
}

func (s *NodeService) ListDeployLogs(ctx context.Context, nodeID string, page, pageSize int) ([]*model.NodeDeployLog, int64, error) {
	nodeUUID, err := uuid.Parse(nodeID)
	if err != nil {
		return nil, 0, ErrInvalidNodeID
	}

	page, pageSize = normalizeNodeListPage(page, pageSize)
	offset := (page - 1) * pageSize

	rows, err := s.pool.Query(
		ctx,
		`SELECT id, node_id, step, progress, message, created_at
		 FROM node_deploy_logs
		 WHERE node_id = $1
		 ORDER BY id DESC
		 LIMIT $2 OFFSET $3`,
		nodeUUID,
		pageSize,
		offset,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	logs := make([]*model.NodeDeployLog, 0, pageSize)
	for rows.Next() {
		item := &model.NodeDeployLog{}
		if err := rows.Scan(&item.ID, &item.NodeID, &item.Step, &item.Progress, &item.Message, &item.CreatedAt); err != nil {
			return nil, 0, err
		}
		logs = append(logs, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var total int64
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM node_deploy_logs WHERE node_id = $1`, nodeUUID).Scan(&total); err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

func (s *NodeService) IsOwner(ctx context.Context, nodeID, userID string) (bool, error) {
	node, err := s.GetByID(ctx, nodeID)
	if err != nil {
		return false, err
	}
	if node.OwnerID == nil {
		return false, nil
	}
	return node.OwnerID.String() == userID, nil
}

func (s *NodeService) WrapRuleRepository(ruleRepo repository.RuleRepository) repository.RuleRepository {
	return NewPortAwareRuleRepository(ruleRepo, s)
}

func (s *NodeService) initializePortPools(ctx context.Context) {
	if s.pool == nil {
		return
	}

	rows, err := s.pool.Query(
		ctx,
		`SELECT id, port_range_min, port_range_max
		 FROM node_agents
		 WHERE port_range_min IS NOT NULL
		   AND port_range_max IS NOT NULL`,
	)
	if err != nil {
		s.logger.Warn("initialize node port pools failed", zap.Error(err))
		return
	}
	defer rows.Close()

	for rows.Next() {
		var nodeID uuid.UUID
		var min int
		var max int
		if err := rows.Scan(&nodeID, &min, &max); err != nil {
			s.logger.Warn("scan node port range failed", zap.Error(err))
			continue
		}

		if min <= 0 || max < min {
			continue
		}

		usedPorts, err := s.loadUsedIngressPorts(ctx, nodeID)
		if err != nil {
			s.logger.Warn(
				"load used ports for node failed",
				zap.String("node_id", nodeID.String()),
				zap.Error(err),
			)
			continue
		}

		s.portPools.Store(nodeID.String(), NewPortPool(nodeID.String(), min, max, usedPorts))
	}

	if err := rows.Err(); err != nil {
		s.logger.Warn("iterate node port ranges failed", zap.Error(err))
	}
}

func (s *NodeService) allocatePortForNode(ctx context.Context, nodeID uuid.UUID) (int, error) {
	pool, err := s.getOrInitPortPool(ctx, nodeID)
	if err != nil {
		return 0, err
	}
	if pool == nil {
		return 0, ErrPortPoolUnavailable
	}
	return pool.Allocate()
}

func (s *NodeService) reservePortForNode(ctx context.Context, nodeID uuid.UUID, port int) error {
	pool, err := s.getOrInitPortPool(ctx, nodeID)
	if err != nil {
		return err
	}
	if pool == nil {
		return ErrPortPoolUnavailable
	}
	return pool.reserve(port)
}

func (s *NodeService) releasePortForNode(nodeID uuid.UUID, port int) {
	if port <= 0 {
		return
	}
	pool, ok := s.loadPortPool(nodeID.String())
	if !ok || pool == nil {
		return
	}
	pool.Release(port)
}

func (s *NodeService) syncPortPoolForNode(ctx context.Context, node *model.NodeAgent) error {
	if node == nil {
		return nil
	}

	min, max, ok := resolveNodePortRange(node)
	if !ok {
		s.portPools.Delete(node.ID.String())
		return nil
	}

	usedPorts, err := s.loadUsedIngressPorts(ctx, node.ID)
	if err != nil {
		return err
	}

	s.portPools.Store(node.ID.String(), NewPortPool(node.ID.String(), min, max, usedPorts))
	return nil
}

func (s *NodeService) getOrInitPortPool(ctx context.Context, nodeID uuid.UUID) (*PortPool, error) {
	if existing, ok := s.loadPortPool(nodeID.String()); ok {
		return existing, nil
	}

	node, err := s.nodeRepo.FindByID(ctx, nodeID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrNodeNotFound
		}
		return nil, err
	}

	min, max, ok := resolveNodePortRange(node)
	if !ok {
		return nil, nil
	}

	usedPorts, err := s.loadUsedIngressPorts(ctx, nodeID)
	if err != nil {
		return nil, err
	}

	newPool := NewPortPool(nodeID.String(), min, max, usedPorts)
	actual, loaded := s.portPools.LoadOrStore(nodeID.String(), newPool)
	if !loaded {
		return newPool, nil
	}

	cached, ok := actual.(*PortPool)
	if !ok {
		s.portPools.Store(nodeID.String(), newPool)
		return newPool, nil
	}
	return cached, nil
}

func (s *NodeService) loadPortPool(nodeID string) (*PortPool, bool) {
	value, ok := s.portPools.Load(nodeID)
	if !ok {
		return nil, false
	}
	pool, ok := value.(*PortPool)
	if !ok {
		s.portPools.Delete(nodeID)
		return nil, false
	}
	return pool, true
}

func (s *NodeService) loadUsedIngressPorts(ctx context.Context, nodeID uuid.UUID) ([]int, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	rows, err := s.pool.Query(
		ctx,
		`SELECT ingress_port
		 FROM forwarding_rules
		 WHERE ingress_node_id = $1
		   AND status != 'deleted'`,
		nodeID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ports := make([]int, 0, 16)
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return ports, nil
}

func resolveNodePortRange(node *model.NodeAgent) (int, int, bool) {
	if node == nil || node.PortRangeMin == nil || node.PortRangeMax == nil {
		return 0, 0, false
	}

	min := *node.PortRangeMin
	max := *node.PortRangeMax
	if min <= 0 || max < min {
		return 0, 0, false
	}

	return min, max, true
}

func (s *NodeService) countNodes(ctx context.Context, filter repository.NodeListFilter) (int64, error) {
	args := make([]any, 0, 4)
	conditions := make([]string, 0, 4)

	if filter.OwnerID != nil {
		args = append(args, *filter.OwnerID)
		conditions = append(conditions, "owner_id = $"+strconv.Itoa(len(args)))
	}
	if filter.Type != nil {
		args = append(args, *filter.Type)
		conditions = append(conditions, "type = $"+strconv.Itoa(len(args)))
	}
	if filter.Status != nil {
		args = append(args, *filter.Status)
		conditions = append(conditions, "status = $"+strconv.Itoa(len(args)))
	}
	if filter.DeployStatus != nil {
		args = append(args, *filter.DeployStatus)
		conditions = append(conditions, "deploy_status = $"+strconv.Itoa(len(args)))
	}

	query := `SELECT COUNT(*) FROM node_agents`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	if err := s.pool.QueryRow(ctx, query, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (s *NodeService) resolveDownloadBaseURL(ctx context.Context) (string, error) {
	var downloadBaseURL string
	err := s.pool.QueryRow(ctx,
		`SELECT COALESCE(telegram_config->>'download_base_url', '') FROM system_configs WHERE id = 1`,
	).Scan(&downloadBaseURL)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}

	downloadBaseURL = strings.TrimSpace(downloadBaseURL)
	if downloadBaseURL == "" {
		downloadBaseURL = strings.TrimSpace(s.cfg.DownloadBaseURL)
	}
	if downloadBaseURL == "" {
		return "", ErrInstallForbidden
	}

	return downloadBaseURL, nil
}

func (s *NodeService) resolveDeployProgressURL() string {
	if strings.TrimSpace(s.cfg.DeployProgress) != "" {
		return strings.TrimSpace(s.cfg.DeployProgress)
	}

	rawHubURL := strings.TrimSpace(s.cfg.HubWSURL)
	if rawHubURL == "" {
		return ""
	}

	parsed, err := url.Parse(rawHubURL)
	if err != nil {
		return ""
	}

	switch parsed.Scheme {
	case "wss":
		parsed.Scheme = "https"
	case "ws":
		parsed.Scheme = "http"
	}

	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.Path = "/api/internal/deploy/progress"

	return parsed.String()
}

func (s *NodeService) collectDeployEventRecipients(ctx context.Context, node *model.NodeAgent) ([]string, error) {
	recipientSet := make(map[string]struct{})
	if node != nil && node.OwnerID != nil {
		recipientSet[node.OwnerID.String()] = struct{}{}
	}

	rows, err := s.pool.Query(ctx, `SELECT id FROM users WHERE role = 'admin'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var adminID uuid.UUID
		if err := rows.Scan(&adminID); err != nil {
			return nil, err
		}
		recipientSet[adminID.String()] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	result := make([]string, 0, len(recipientSet))
	for userID := range recipientSet {
		result = append(result, userID)
	}
	return result, nil
}

func (s *NodeService) writeAudit(
	ctx context.Context,
	operatorID string,
	action string,
	resourceID string,
	oldValue map[string]interface{},
	newValue map[string]interface{},
) {
	if s.auditRepo == nil {
		return
	}

	var actorID *uuid.UUID
	if operatorID != "" {
		if parsed, err := uuid.Parse(operatorID); err == nil {
			actorID = &parsed
		}
	}

	_ = s.auditRepo.Create(ctx, &model.AuditLog{
		UserID:       actorID,
		Action:       action,
		ResourceType: strPtr("node"),
		ResourceID:   strPtr(resourceID),
		OldValue:     oldValue,
		NewValue:     newValue,
		CreatedAt:    time.Now().UTC(),
	})
}

func normalizeNodeListPage(page, pageSize int) (int, int) {
	if page <= 0 {
		page = nodeListDefaultPage
	}
	if pageSize <= 0 {
		pageSize = nodeListDefaultSize
	}
	if pageSize > nodeListMaxPageSize {
		pageSize = nodeListMaxPageSize
	}
	return page, pageSize
}

func generateHexToken(byteLen int) (string, error) {
	if byteLen <= 0 {
		byteLen = 32
	}

	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func computeScriptChecksum(scriptContent, installToken string) string {
	mac := hmac.New(sha256.New, []byte(installToken))
	_, _ = mac.Write([]byte(scriptContent))
	return hex.EncodeToString(mac.Sum(nil))
}

func injectScriptChecksum(scriptContent, checksum string) string {
	normalized := strings.TrimRight(scriptContent, "\n")
	if normalized == "" {
		return "# nodepass-checksum: " + checksum + "\n"
	}

	lines := strings.Split(normalized, "\n")
	checksumLine := "# nodepass-checksum: " + checksum

	if strings.HasPrefix(lines[0], "#!") {
		result := make([]string, 0, len(lines)+1)
		result = append(result, lines[0], checksumLine)
		result = append(result, lines[1:]...)
		return strings.Join(result, "\n") + "\n"
	}

	return checksumLine + "\n" + normalized + "\n"
}

func sanitizeNode(node *model.NodeAgent) *model.NodeAgent {
	if node == nil {
		return nil
	}
	copyNode := cloneNode(node)
	copyNode.Token = ""
	return copyNode
}

func cloneNode(node *model.NodeAgent) *model.NodeAgent {
	if node == nil {
		return nil
	}
	copied := *node
	if node.OwnerID != nil {
		owner := *node.OwnerID
		copied.OwnerID = &owner
	}
	if node.PortRangeMin != nil {
		min := *node.PortRangeMin
		copied.PortRangeMin = &min
	}
	if node.PortRangeMax != nil {
		max := *node.PortRangeMax
		copied.PortRangeMax = &max
	}
	if node.AgentVersion != nil {
		version := *node.AgentVersion
		copied.AgentVersion = &version
	}
	if node.LastSeenAt != nil {
		lastSeen := *node.LastSeenAt
		copied.LastSeenAt = &lastSeen
	}
	if node.InstallScriptExpiresAt != nil {
		expiresAt := *node.InstallScriptExpiresAt
		copied.InstallScriptExpiresAt = &expiresAt
	}
	if node.DeployError != nil {
		errText := *node.DeployError
		copied.DeployError = &errText
	}
	if node.SysInfo != nil {
		sysInfo := make(map[string]interface{}, len(node.SysInfo))
		for k, v := range node.SysInfo {
			sysInfo[k] = v
		}
		copied.SysInfo = sysInfo
	}
	return &copied
}
