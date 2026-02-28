package api

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	externalapi "nodepass-hub/internal/api/external"
	internalapi "nodepass-hub/internal/api/internal"
	"nodepass-hub/internal/repository"
	"nodepass-hub/internal/service"
)

func RegisterInternalRoutes(
	router gin.IRoutes,
	nodeService *service.NodeService,
	trafficService service.TrafficService,
	policyService *service.PolicyService,
	agentHMACSecret string,
) {
	secret := strings.TrimSpace(agentHMACSecret)
	if nodeService != nil {
		internalapi.RegisterDeployInternalRoutes(router, nodeService, secret)
	}
	if trafficService != nil {
		internalapi.RegisterTrafficInternalRoutes(router, trafficService, secret)
	}
	if policyService != nil {
		internalapi.RegisterPolicyInternalRoutes(router, policyService)
	}
}

func RegisterExternalRoutes(
	router gin.IRoutes,
	pool *pgxpool.Pool,
	userService *service.UserService,
	vipService *service.VIPService,
	ruleService *service.RuleService,
	auditRepo repository.AuditRepository,
	logger *zap.Logger,
) {
	externalapi.RegisterRoutes(router, pool, userService, vipService, ruleService, auditRepo, logger)
}
