package v1

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository/postgres"
	"nodepass-hub/internal/service"
)

type redeemHistoryAPIResponse struct {
	Code       int                      `json:"code"`
	Message    string                   `json:"message"`
	Data       []redeemHistoryAPIRecord `json:"data"`
	Pagination struct {
		Page     int `json:"page"`
		PageSize int `json:"page_size"`
		Total    int `json:"total"`
	} `json:"pagination"`
}

type redeemHistoryAPIRecord struct {
	ID           string `json:"id"`
	Code         string `json:"code"`
	VIPLevel     int    `json:"vip_level"`
	DurationDays int    `json:"duration_days"`
	UsedAt       string `json:"used_at"`
	ExpiresAt    string `json:"expires_at"`
	Source       string `json:"source"`
	Remark       string `json:"remark"`
}

func TestListRedeemHistory_UserIsolationAndPagination(t *testing.T) {
	router, pool := setupCodeHistoryTestServer(t)

	ctx := context.Background()
	userA := seedCodeHistoryUser(t, ctx, pool, "history_user_a", "pass-a-123")
	userB := seedCodeHistoryUser(t, ctx, pool, "history_user_b", "pass-b-123")
	seedVIPLevel(t, ctx, pool, 1)
	seedVIPLevel(t, ctx, pool, 2)
	seedVIPLevel(t, ctx, pool, 3)

	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	seedUsedBenefitCode(t, ctx, pool, "VIP-A-001", userA.ID, 2, 30, base.Add(3*time.Minute))
	seedUsedBenefitCode(t, ctx, pool, "VIP-A-002", userA.ID, 1, 15, base.Add(2*time.Minute))
	seedUsedBenefitCode(t, ctx, pool, "VIP-A-003", userA.ID, 1, 7, base.Add(1*time.Minute))
	seedUsedBenefitCode(t, ctx, pool, "VIP-B-001", userB.ID, 3, 60, base.Add(4*time.Minute))

	userACookies := loginCookiesForCodeTest(t, router, "history_user_a", "pass-a-123")
	resp := performJSONRequest(
		t,
		router,
		http.MethodGet,
		"/api/v1/codes/redeem/history?page=1&page_size=2",
		nil,
		userACookies,
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.Code)
	}

	page1 := decodeRedeemHistoryAPIResponse(t, resp.Body.Bytes())
	if page1.Code != 0 {
		t.Fatalf("expected app code 0, got %d", page1.Code)
	}
	if page1.Pagination.Page != 1 || page1.Pagination.PageSize != 2 {
		t.Fatalf("unexpected pagination: %+v", page1.Pagination)
	}
	if page1.Pagination.Total != 3 {
		t.Fatalf("expected total=3, got %d", page1.Pagination.Total)
	}
	if len(page1.Data) != 2 {
		t.Fatalf("expected 2 records on first page, got %d", len(page1.Data))
	}
	if page1.Data[0].Code != "VIP-A-001" || page1.Data[1].Code != "VIP-A-002" {
		t.Fatalf("unexpected page1 order: %+v", page1.Data)
	}
	for _, item := range page1.Data {
		if item.Source != "benefit_code" {
			t.Fatalf("expected source=benefit_code, got %q", item.Source)
		}
		if item.Remark == "" {
			t.Fatalf("expected remark to be non-empty for item %s", item.ID)
		}
		usedAt, err := time.Parse(time.RFC3339Nano, item.UsedAt)
		if err != nil {
			t.Fatalf("invalid used_at %q: %v", item.UsedAt, err)
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, item.ExpiresAt)
		if err != nil {
			t.Fatalf("invalid expires_at %q: %v", item.ExpiresAt, err)
		}
		expectedExpire := usedAt.AddDate(0, 0, item.DurationDays).UTC()
		if !expiresAt.UTC().Equal(expectedExpire) {
			t.Fatalf("unexpected expires_at: got=%s want=%s", expiresAt.UTC(), expectedExpire)
		}
		if item.Code == "VIP-B-001" {
			t.Fatal("user A response leaked user B record")
		}
	}

	respPage2 := performJSONRequest(
		t,
		router,
		http.MethodGet,
		"/api/v1/codes/redeem/history?page=2&page_size=2",
		nil,
		userACookies,
	)
	if respPage2.Code != http.StatusOK {
		t.Fatalf("expected page2 status 200, got %d", respPage2.Code)
	}
	page2 := decodeRedeemHistoryAPIResponse(t, respPage2.Body.Bytes())
	if len(page2.Data) != 1 {
		t.Fatalf("expected 1 record on second page, got %d", len(page2.Data))
	}
	if page2.Data[0].Code != "VIP-A-003" {
		t.Fatalf("unexpected page2 code: %+v", page2.Data[0])
	}

	userBCookies := loginCookiesForCodeTest(t, router, "history_user_b", "pass-b-123")
	respUserB := performJSONRequest(
		t,
		router,
		http.MethodGet,
		"/api/v1/codes/redeem/history?page=1&page_size=10",
		nil,
		userBCookies,
	)
	if respUserB.Code != http.StatusOK {
		t.Fatalf("expected user B status 200, got %d", respUserB.Code)
	}
	userBPage := decodeRedeemHistoryAPIResponse(t, respUserB.Body.Bytes())
	if userBPage.Pagination.Total != 1 || len(userBPage.Data) != 1 {
		t.Fatalf("expected only one record for user B, got total=%d len=%d", userBPage.Pagination.Total, len(userBPage.Data))
	}
	if userBPage.Data[0].Code != "VIP-B-001" {
		t.Fatalf("unexpected user B code: %+v", userBPage.Data[0])
	}
}

func TestListRedeemHistory_Unauthorized(t *testing.T) {
	router, _ := setupCodeHistoryTestServer(t)

	resp := performJSONRequest(
		t,
		router,
		http.MethodGet,
		"/api/v1/codes/redeem/history",
		nil,
		nil,
	)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", resp.Code)
	}

	body := decodeAPIResponse(t, resp.Body.Bytes())
	if body.Code != 10001 {
		t.Fatalf("expected app code 10001, got %d", body.Code)
	}
}

func setupCodeHistoryTestServer(t *testing.T) (*gin.Engine, *pgxpool.Pool) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	pool := startPostgresForAuthTest(t)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	setJWTEnvForCodeTest(t, &privateKey.PublicKey)

	userRepo := postgres.NewUserRepository(pool)
	codeRepo := postgres.NewBenefitCodeRepository(pool)

	authSvc := service.NewAuthService(userRepo, nil, pool, privateKey)
	systemSvc := service.NewSystemService(pool, nil, nil, nil)
	codeSvc := service.NewBenefitCodeService(codeRepo, nil, pool, nil, nil, nil)

	router := gin.New()
	group := router.Group("/api/v1")
	RegisterAuthRoutes(group, authSvc, systemSvc)
	RegisterCodeRoutes(group, codeSvc)

	return router, pool
}

func setJWTEnvForCodeTest(t *testing.T, publicKey *rsa.PublicKey) {
	t.Helper()

	block := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(publicKey),
	}
	t.Setenv("NODEPASS_JWT_PUBLIC_KEY", string(pem.EncodeToMemory(block)))
	t.Setenv("NODEPASS_JWT_PUBLIC_KEY_FILE", "")
}

func seedCodeHistoryUser(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	username string,
	password string,
) *model.User {
	t.Helper()

	userRepo := postgres.NewUserRepository(pool)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	user := &model.User{
		ID:           uuid.New(),
		Username:     username,
		PasswordHash: string(hashedPassword),
		Role:         model.UserRoleUser,
		Status:       model.UserStatusNormal,
		TrafficQuota: 1 << 30,
		MaxRules:     5,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
	if err := userRepo.Create(ctx, user); err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	return user
}

func seedUsedBenefitCode(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	code string,
	userID uuid.UUID,
	vipLevel int,
	durationDays int,
	usedAt time.Time,
) {
	t.Helper()

	_, err := pool.Exec(
		ctx,
		`INSERT INTO benefit_codes (
			id, code, vip_level, duration_days, expires_at, valid_days,
			is_used, is_enabled, used_by, used_at, created_by, created_at
		) VALUES (
			$1, $2, $3, $4, NULL, 365,
			TRUE, TRUE, $5, $6, $7, $8
		)`,
		uuid.New(),
		code,
		vipLevel,
		durationDays,
		userID,
		usedAt.UTC(),
		userID,
		usedAt.UTC().Add(-5*time.Minute),
	)
	if err != nil {
		t.Fatalf("insert benefit code %s: %v", code, err)
	}
}

func seedVIPLevel(t *testing.T, ctx context.Context, pool *pgxpool.Pool, level int) {
	t.Helper()

	_, err := pool.Exec(
		ctx,
		`INSERT INTO vip_levels (
			level, name, traffic_quota, max_rules, bandwidth_limit,
			max_ingress_nodes, max_egress_nodes, accessible_node_level, traffic_ratio
		) VALUES ($1, $2, $3, $4, $5, 0, 0, 0, 1.0)
		ON CONFLICT (level) DO NOTHING`,
		level,
		fmt.Sprintf("VIP %d", level),
		int64(1<<30),
		10,
		int64(0),
	)
	if err != nil {
		t.Fatalf("insert vip level %d: %v", level, err)
	}
}

func loginCookiesForCodeTest(t *testing.T, router *gin.Engine, username, password string) []*http.Cookie {
	t.Helper()

	resp := performJSONRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/auth/login",
		map[string]any{
			"username": username,
			"password": password,
		},
		nil,
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("login failed for %s: status=%d body=%s", username, resp.Code, resp.Body.String())
	}

	access := findCookieByName(resp.Result().Cookies(), accessTokenCookieName)
	if access == nil || access.Value == "" {
		t.Fatalf("missing access token cookie for %s", username)
	}
	refresh := findCookieByName(resp.Result().Cookies(), refreshTokenCookieName)
	if refresh == nil || refresh.Value == "" {
		t.Fatalf("missing refresh token cookie for %s", username)
	}
	return []*http.Cookie{access, refresh}
}

func decodeRedeemHistoryAPIResponse(t *testing.T, raw []byte) redeemHistoryAPIResponse {
	t.Helper()

	var resp redeemHistoryAPIResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func (r redeemHistoryAPIRecord) String() string {
	return fmt.Sprintf("%s(%s)", r.Code, r.ID)
}
