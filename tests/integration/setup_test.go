//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"nodepass-hub/internal/api"
	"nodepass-hub/internal/api/response"
	v1 "nodepass-hub/internal/api/v1"
	"nodepass-hub/internal/event"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
	"nodepass-hub/internal/repository/postgres"
	"nodepass-hub/internal/service"
	"nodepass-hub/internal/sse"
)

const (
	adminPassword = "AdminPass123!"
	userPassword  = "UserPass123!"
)

type apiEnvelope struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

type loginSessionResult struct {
	AccessToken  string
	RefreshToken string
	AccessCookie *http.Cookie
	AllCookies   []*http.Cookie
}

type integrationRuleHub struct {
	mu      sync.Mutex
	actions []string
}

func (h *integrationRuleHub) SendConfigPushAndWaitAck(
	_ context.Context,
	_ string,
	ruleID string,
	action string,
	_ string,
	_ string,
	_ time.Duration,
) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.actions = append(h.actions, fmt.Sprintf("%s:%s", ruleID, action))
	return true, nil
}

type integrationEnv struct {
	pool                *pgxpool.Pool
	router              *gin.Engine
	privateKey          *rsa.PrivateKey
	internalSecret      string
	adminID             uuid.UUID
	adminUsername       string
	defaultUserID       uuid.UUID
	defaultUserUsername string

	userRepo     repository.UserRepository
	nodeService  *service.NodeService
	ruleService  *service.RuleService
	trafficSvc   service.TrafficService
	codeService  *service.BenefitCodeService
	sseHub       *sse.SSEHub
	mockRuleHub  *integrationRuleHub
	systemSvc    *service.SystemService
	authSvc      *service.AuthService
	notifySvc    *service.NotificationService
	benefitSvc   *service.BenefitCodeService
	vipSvc       *service.VIPService
	policySvc    *service.PolicyService
	announcement *service.AnnouncementService
}

var suite *integrationEnv

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	env, err := buildIntegrationEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "integration setup failed: %v\n", err)
		os.Exit(1)
	}
	suite = env

	code := m.Run()

	if suite != nil {
		if suite.sseHub != nil {
			suite.sseHub.Close()
		}
		if suite.pool != nil {
			suite.pool.Close()
		}
	}

	os.Exit(code)
}

func buildIntegrationEnv() (*integrationEnv, error) {
	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "postgres:16-alpine",
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":     "postgres",
				"POSTGRES_PASSWORD": "postgres",
				"POSTGRES_DB":       "nodepass_test",
			},
			WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(90 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		return nil, err
	}

	host, err := container.Host(ctx)
	if err != nil {
		return nil, err
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return nil, err
	}

	dsn := fmt.Sprintf("postgres://postgres:postgres@%s:%s/nodepass_test?sslmode=disable", host, port.Port())
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		if pingErr := pool.Ping(ctx); pingErr == nil {
			break
		}
		if time.Now().After(deadline) {
			return nil, errors.New("postgres did not become ready")
		}
		time.Sleep(500 * time.Millisecond)
	}

	if err := applyAllMigrations(ctx, pool); err != nil {
		return nil, err
	}
	if err := seedVIPLevels(ctx, pool); err != nil {
		return nil, err
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := setPublicKeyEnv(privateKey); err != nil {
		return nil, err
	}

	logger := zap.NewNop()
	userRepo := postgres.NewUserRepository(pool)
	nodeRepo := postgres.NewNodeRepository(pool)
	ruleRepo := postgres.NewRuleRepository(pool)
	trafficRepo := postgres.NewTrafficRepository(pool)
	auditRepo := postgres.NewAuditRepository(pool)
	benefitCodeRepo := postgres.NewBenefitCodeRepository(pool)

	sseHub := sse.NewHub(logger)
	eventBus := event.NewBus()
	internalSecret := "integration-secret"
	mockRuleHub := &integrationRuleHub{}

	nodeSvc := service.NewNodeService(nodeRepo, auditRepo, sseHub, pool, service.NodeServiceConfig{
		HMACSecret: internalSecret,
	}, logger)
	ruleSvc := service.NewRuleService(
		ruleRepo,
		userRepo,
		nodeRepo,
		auditRepo,
		pool,
		mockRuleHub,
		sseHub,
		nil,
		nil,
		nodeSvc,
		logger,
	)
	trafficSvc := service.NewTrafficService(trafficRepo, userRepo, ruleRepo, auditRepo, pool, eventBus, logger)
	vipSvc := service.NewVIPService(userRepo, auditRepo, pool, ruleSvc, eventBus, sseHub, logger)
	benefitSvc := service.NewBenefitCodeService(benefitCodeRepo, auditRepo, pool, vipSvc, sseHub, logger)
	systemSvc := service.NewSystemService(pool, auditRepo, sseHub, logger)
	notifySvc := service.NewNotificationService(userRepo, systemSvc, pool, logger)
	policySvc := service.NewPolicyService(pool, ruleSvc, trafficSvc, logger)
	announcementSvc := service.NewAnnouncementService(pool, auditRepo, sseHub, logger)
	authSvc := service.NewAuthService(userRepo, auditRepo, pool, privateKey)
	userSvc := service.NewUserService(userRepo, auditRepo)

	if _, err := systemSvc.GetConfig(context.Background()); err != nil {
		return nil, err
	}

	adminID, err := seedUser(ctx, userRepo, "admin_integration", adminPassword, model.UserRoleAdmin)
	if err != nil {
		return nil, err
	}
	userID, err := seedUser(ctx, userRepo, "alice_integration", userPassword, model.UserRoleUser)
	if err != nil {
		return nil, err
	}

	router := gin.New()
	apiV1 := router.Group("/api/v1")
	v1.RegisterAuthRoutes(apiV1, authSvc, systemSvc)
	v1.RegisterUserRoutes(apiV1, userSvc)
	v1.RegisterNodeRoutes(apiV1, nodeSvc)
	v1.RegisterRuleRoutes(apiV1, ruleSvc)
	v1.RegisterTrafficRoutes(apiV1, trafficSvc, ruleSvc)
	v1.RegisterSSERoutes(apiV1, sseHub)
	api.RegisterInternalRoutes(router, nodeSvc, trafficSvc, policySvc, internalSecret)

	return &integrationEnv{
		pool:                pool,
		router:              router,
		privateKey:          privateKey,
		internalSecret:      internalSecret,
		adminID:             adminID,
		adminUsername:       "admin_integration",
		defaultUserID:       userID,
		defaultUserUsername: "alice_integration",
		userRepo:            userRepo,
		nodeService:         nodeSvc,
		ruleService:         ruleSvc,
		trafficSvc:          trafficSvc,
		codeService:         benefitSvc,
		sseHub:              sseHub,
		mockRuleHub:         mockRuleHub,
		systemSvc:           systemSvc,
		authSvc:             authSvc,
		notifySvc:           notifySvc,
		benefitSvc:          benefitSvc,
		vipSvc:              vipSvc,
		policySvc:           policySvc,
		announcement:        announcementSvc,
	}, nil
}

func setPublicKeyEnv(privateKey *rsa.PrivateKey) error {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})
	return os.Setenv("NODEPASS_JWT_PUBLIC_KEY", string(publicPEM))
}

func applyAllMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	migrationsDir, err := findMigrationsDir()
	if err != nil {
		return err
	}

	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return err
	}

	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		files = append(files, entry.Name())
	}
	sort.Strings(files)

	for _, file := range files {
		// #nosec G304 -- migration file list comes from controlled test directory.
		raw, err := os.ReadFile(filepath.Join(migrationsDir, file))
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(raw)) == "" {
			continue
		}
		if _, err := pool.Exec(ctx, string(raw)); err != nil {
			return err
		}
	}

	return nil
}

func findMigrationsDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		candidate := filepath.Join(dir, "migrations")
		if stat, err := os.Stat(candidate); err == nil && stat.IsDir() {
			return candidate, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("could not locate migrations directory")
		}
		dir = parent
	}
}

func seedVIPLevels(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(
		ctx,
		`INSERT INTO vip_levels (
			level, name, traffic_quota, max_rules, bandwidth_limit,
			max_ingress_nodes, max_egress_nodes, accessible_node_level,
			traffic_ratio, custom_features, created_at
		) VALUES
			(0, 'Free', 1073741824, 5, 0, 0, 0, 0, 1.0, '{}'::jsonb, NOW()),
			(1, 'VIP-1', 5368709120, 20, 100, 5, 5, 0, 1.2, '{}'::jsonb, NOW())
		ON CONFLICT (level) DO NOTHING`,
	)
	return err
}

func seedUser(
	ctx context.Context,
	repo repository.UserRepository,
	username string,
	password string,
	role model.UserRole,
) (uuid.UUID, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return uuid.Nil, err
	}

	user := &model.User{
		ID:           uuid.New(),
		Username:     username,
		PasswordHash: string(hashedPassword),
		Role:         role,
		Status:       model.UserStatusNormal,
		TrafficQuota: 1 << 40,
		MaxRules:     50,
		VIPLevel:     0,
	}
	if err := repo.Create(ctx, user); err != nil {
		return uuid.Nil, err
	}

	return user.ID, nil
}

func getEnv(t *testing.T) *integrationEnv {
	t.Helper()
	if suite == nil {
		t.Fatal("integration environment not initialized")
	}
	return suite
}

func loginAs(t *testing.T, username string, password string) string {
	t.Helper()

	accessToken, _, err := getEnv(t).authSvc.Login(context.Background(), username, password)
	if err != nil {
		t.Fatalf("service login failed: %v", err)
	}
	return accessToken
}

func loginSession(t *testing.T, username string, password string) loginSessionResult {
	t.Helper()
	env := getEnv(t)

	resp := performJSONRequest(
		t,
		env.router,
		http.MethodPost,
		"/api/v1/auth/login",
		map[string]interface{}{
			"username": username,
			"password": password,
		},
		nil,
		nil,
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("login failed, status=%d body=%s", resp.Code, resp.Body.String())
	}

	envelope := decodeEnvelope(t, resp)
	if envelope.Code != 0 {
		t.Fatalf("login failed, code=%d message=%s", envelope.Code, envelope.Message)
	}

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(envelope.Data, &payload); err != nil {
		t.Fatalf("decode login payload: %v", err)
	}

	result := loginSessionResult{
		AccessToken:  payload.AccessToken,
		RefreshToken: payload.RefreshToken,
		AllCookies:   resp.Result().Cookies(),
	}
	for _, cookie := range result.AllCookies {
		if cookie == nil {
			continue
		}
		if cookie.Name == "access_token" {
			result.AccessCookie = cookie
		}
	}

	return result
}

func authHeader(token string) map[string]string {
	return map[string]string{
		"Authorization": "Bearer " + token,
	}
}

func createRegularUser(t *testing.T) (model.User, string) {
	t.Helper()

	adminToken := loginAs(t, getEnv(t).adminUsername, adminPassword)
	username := uniqueName("user")
	password := "UserPass123!"

	resp := performJSONRequest(
		t,
		getEnv(t).router,
		http.MethodPost,
		"/api/v1/users/",
		map[string]interface{}{
			"username": username,
			"password": password,
			"role":     "user",
			"status":   "normal",
		},
		authHeader(adminToken),
		nil,
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("create user failed, status=%d body=%s", resp.Code, resp.Body.String())
	}

	envelope := decodeEnvelope(t, resp)
	if envelope.Code != 0 {
		t.Fatalf("create user failed, code=%d", envelope.Code)
	}

	var user model.User
	if err := json.Unmarshal(envelope.Data, &user); err != nil {
		t.Fatalf("decode user payload: %v", err)
	}

	token := loginAs(t, username, password)
	return user, token
}

func createNode(t *testing.T, token string) *model.NodeAgent {
	t.Helper()

	payload := map[string]interface{}{
		"name":           uniqueName("node"),
		"type":           "entry",
		"host":           "127.0.0.1",
		"api_port":       9000,
		"arch":           "amd64",
		"is_self_hosted": true,
		"port_range_min": 30000,
		"port_range_max": 30100,
	}
	resp := performJSONRequest(t, getEnv(t).router, http.MethodPost, "/api/v1/nodes/", payload, authHeader(token), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("create node failed, status=%d body=%s", resp.Code, resp.Body.String())
	}

	envelope := decodeEnvelope(t, resp)
	if envelope.Code != 0 {
		t.Fatalf("create node failed, code=%d message=%s", envelope.Code, envelope.Message)
	}

	var node model.NodeAgent
	if err := json.Unmarshal(envelope.Data, &node); err != nil {
		t.Fatalf("decode node payload: %v", err)
	}

	return &node
}

func createRule(t *testing.T, token string, nodeID uuid.UUID) *model.ForwardingRule {
	t.Helper()

	payload := map[string]interface{}{
		"name":            uniqueName("rule"),
		"mode":            "single",
		"ingress_node_id": nodeID.String(),
		"target_host":     "example.com",
		"target_port":     443,
	}
	resp := performJSONRequest(t, getEnv(t).router, http.MethodPost, "/api/v1/rules/", payload, authHeader(token), nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("create rule failed, status=%d body=%s", resp.Code, resp.Body.String())
	}

	envelope := decodeEnvelope(t, resp)
	if envelope.Code != 0 {
		t.Fatalf("create rule failed, code=%d message=%s", envelope.Code, envelope.Message)
	}

	var rule model.ForwardingRule
	if err := json.Unmarshal(envelope.Data, &rule); err != nil {
		t.Fatalf("decode rule payload: %v", err)
	}

	return &rule
}

func setNodeOnline(t *testing.T, nodeID uuid.UUID) {
	t.Helper()

	if err := getEnv(t).nodeService.UpdateStatus(context.Background(), nodeID.String(), "online"); err != nil {
		t.Fatalf("set node online failed: %v", err)
	}
}

func userByID(t *testing.T, id uuid.UUID) *model.User {
	t.Helper()

	user, err := getEnv(t).userRepo.FindByID(context.Background(), id)
	if err != nil {
		t.Fatalf("query user by id failed: %v", err)
	}
	return user
}

func performJSONRequest(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	payload interface{},
	headers map[string]string,
	cookies []*http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()

	var body []byte
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		body = raw
	}

	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	for _, cookie := range cookies {
		if cookie != nil {
			req.AddCookie(cookie)
		}
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	return recorder
}

func decodeEnvelope(t *testing.T, resp *httptest.ResponseRecorder) apiEnvelope {
	t.Helper()

	var envelope apiEnvelope
	if err := json.Unmarshal(resp.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response body: %v, raw=%s", err, resp.Body.String())
	}
	return envelope
}

func uniqueName(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func getDefaultUser(t *testing.T) *model.User {
	t.Helper()
	user, err := getEnv(t).userRepo.FindByID(context.Background(), getEnv(t).defaultUserID)
	if err != nil {
		t.Fatalf("query default user failed: %v", err)
	}
	return user
}

func mustUUID(t *testing.T, raw string) uuid.UUID {
	t.Helper()
	value, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		t.Fatalf("parse uuid failed: %v", err)
	}
	return value
}

func hasResponseCode(resp *httptest.ResponseRecorder, code int) bool {
	return resp != nil && resp.Code == code
}

func responseCode(resp *httptest.ResponseRecorder) int {
	if resp == nil {
		return response.ErrInternal
	}
	envelope := apiEnvelope{}
	_ = json.Unmarshal(resp.Body.Bytes(), &envelope)
	return envelope.Code
}
