package v1

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/bcrypt"

	"nodepass-hub/internal/api/response"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository/postgres"
	"nodepass-hub/internal/service"
)

type apiResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

func TestLogin_Success_SetsCookie(t *testing.T) {
	router, _ := setupAuthTestServer(t)

	resp := performJSONRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/auth/login",
		map[string]any{"username": "tester", "password": "password123"},
		nil,
	)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.Code)
	}

	body := decodeAPIResponse(t, resp.Body.Bytes())
	if body.Code != 0 {
		t.Fatalf("expected response code 0, got %d", body.Code)
	}

	accessCookie := findCookieByName(resp.Result().Cookies(), accessTokenCookieName)
	if accessCookie == nil || accessCookie.Value == "" {
		t.Fatal("expected access_token cookie to be set")
	}
	if !accessCookie.HttpOnly || !accessCookie.Secure {
		t.Fatalf("expected secure httponly access cookie, got %+v", accessCookie)
	}

	refreshCookie := findCookieByName(resp.Result().Cookies(), refreshTokenCookieName)
	if refreshCookie == nil || refreshCookie.Value == "" {
		t.Fatal("expected refresh_token cookie to be set")
	}
	if !refreshCookie.HttpOnly || !refreshCookie.Secure {
		t.Fatalf("expected secure httponly refresh cookie, got %+v", refreshCookie)
	}
}

func TestLogin_WrongPassword_Returns401(t *testing.T) {
	router, _ := setupAuthTestServer(t)

	resp := performJSONRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/auth/login",
		map[string]any{"username": "tester", "password": "wrong-password"},
		nil,
	)
	if resp.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d", resp.Code)
	}

	body := decodeAPIResponse(t, resp.Body.Bytes())
	if body.Code != response.ErrPasswordWrong {
		t.Fatalf("expected app code %d, got %d", response.ErrPasswordWrong, body.Code)
	}
}

func TestRefreshToken_Rotation_OldTokenInvalidated(t *testing.T) {
	router, _ := setupAuthTestServer(t)

	loginResp := performJSONRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/auth/login",
		map[string]any{"username": "tester", "password": "password123"},
		nil,
	)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("expected login status 200, got %d", loginResp.Code)
	}

	oldRefresh := findCookieByName(loginResp.Result().Cookies(), refreshTokenCookieName)
	if oldRefresh == nil || oldRefresh.Value == "" {
		t.Fatal("expected initial refresh token cookie")
	}

	refreshResp := performJSONRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/auth/refresh",
		nil,
		[]*http.Cookie{oldRefresh},
	)
	if refreshResp.Code != http.StatusOK {
		t.Fatalf("expected refresh status 200, got %d", refreshResp.Code)
	}

	newRefresh := findCookieByName(refreshResp.Result().Cookies(), refreshTokenCookieName)
	if newRefresh == nil || newRefresh.Value == "" {
		t.Fatal("expected rotated refresh token cookie")
	}
	if newRefresh.Value == oldRefresh.Value {
		t.Fatal("expected rotated refresh token to differ from previous token")
	}

	staleResp := performJSONRequest(
		t,
		router,
		http.MethodPost,
		"/api/v1/auth/refresh",
		nil,
		[]*http.Cookie{oldRefresh},
	)
	if staleResp.Code != http.StatusUnauthorized {
		t.Fatalf("expected stale token status 401, got %d", staleResp.Code)
	}

	body := decodeAPIResponse(t, staleResp.Body.Bytes())
	if body.Code != response.ErrUnauthorized {
		t.Fatalf("expected app code %d, got %d", response.ErrUnauthorized, body.Code)
	}
}

func setupAuthTestServer(t *testing.T) (*gin.Engine, *pgxpool.Pool) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	pool := startPostgresForAuthTest(t)
	userRepo := postgres.NewUserRepository(pool)

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	user := &model.User{
		ID:           uuid.New(),
		Username:     "tester",
		PasswordHash: string(hashedPassword),
		Role:         model.UserRoleUser,
		Status:       model.UserStatusNormal,
		TrafficQuota: 1 << 40,
		MaxRules:     5,
	}
	if err := userRepo.Create(context.Background(), user); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	authSvc := service.NewAuthService(userRepo, nil, pool, privateKey)
	systemSvc := service.NewSystemService(pool, nil, nil, nil)

	router := gin.New()
	group := router.Group("/api/v1")
	RegisterAuthRoutes(group, authSvc, systemSvc)

	return router, pool
}

func performJSONRequest(
	t *testing.T,
	router http.Handler,
	method string,
	path string,
	payload map[string]any,
	cookies []*http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()

	var bodyBytes []byte
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		bodyBytes = raw
	}

	req := httptest.NewRequest(method, path, bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	for _, cookie := range cookies {
		if cookie != nil {
			req.AddCookie(cookie)
		}
	}

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, req)
	return resp
}

func decodeAPIResponse(t *testing.T, raw []byte) apiResponse {
	t.Helper()

	var resp apiResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("decode response body: %v", err)
	}
	return resp
}

func findCookieByName(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func startPostgresForAuthTest(t *testing.T) *pgxpool.Pool {
	t.Helper()
	testcontainers.SkipIfProviderIsNotHealthy(t)

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
		t.Skipf("skipping test because docker/testcontainers is unavailable: %v", err)
	}

	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}
	port, err := container.MappedPort(ctx, "5432/tcp")
	if err != nil {
		t.Fatalf("container mapped port: %v", err)
	}

	dsn := fmt.Sprintf("postgres://postgres:postgres@%s:%s/nodepass_test?sslmode=disable", host, port.Port())
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("create pgx pool: %v", err)
	}
	t.Cleanup(pool.Close)

	deadline := time.Now().Add(30 * time.Second)
	for {
		err = pool.Ping(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("postgres did not become ready: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	applyMigrationsForAuthTest(t, ctx, pool)
	return pool
}

func applyMigrationsForAuthTest(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	migrationsDir := filepath.Join(findRepoRootForAuthTest(t), "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		t.Fatalf("read migrations dir: %v", err)
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
		raw, err := os.ReadFile(filepath.Join(migrationsDir, file))
		if err != nil {
			t.Fatalf("read migration %s: %v", file, err)
		}
		if strings.TrimSpace(string(raw)) == "" {
			continue
		}
		if _, err := pool.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("apply migration %s: %v", file, err)
		}
	}
}

func findRepoRootForAuthTest(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	for {
		_, statErr := os.Stat(filepath.Join(dir, "go.mod"))
		if statErr == nil {
			return dir
		}
		if !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("stat go.mod: %v", statErr)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repository root")
		}
		dir = parent
	}
}
