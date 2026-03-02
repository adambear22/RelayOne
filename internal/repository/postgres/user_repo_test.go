package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	testcontainers "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"nodepass-hub/internal/model"
)

func TestUpdateTrafficUsed_AtomicIncrement(t *testing.T) {
	pool := startPostgresForTest(t)
	repo := NewUserRepository(pool)
	ctx := context.Background()

	user := &model.User{
		ID:           uuid.New(),
		Username:     "atomic_user",
		PasswordHash: "hash",
		Role:         model.UserRoleUser,
		Status:       model.UserStatusNormal,
		TrafficQuota: 1 << 40,
		TrafficUsed:  0,
		MaxRules:     5,
	}
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	const workers = 100
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- repo.UpdateTrafficUsed(ctx, user.ID, 1)
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("UpdateTrafficUsed returned error: %v", err)
		}
	}

	got, err := repo.FindByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}

	if got.TrafficUsed != workers {
		t.Fatalf("expected traffic_used=%d, got %d", workers, got.TrafficUsed)
	}
}

func TestFindByUsername_NotFound(t *testing.T) {
	pool := startPostgresForTest(t)
	repo := NewUserRepository(pool)

	user, err := repo.FindByUsername(context.Background(), "missing-user")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if user != nil {
		t.Fatalf("expected nil user, got %+v", user)
	}
}

func startPostgresForTest(t *testing.T) *pgxpool.Pool {
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

	applyAllMigrations(t, ctx, pool)
	return pool
}

func applyAllMigrations(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()

	migrationsDir := filepath.Join(findRepoRoot(t), "migrations")
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
		// #nosec G304 -- migration file list comes from controlled test directory.
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

func findRepoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repository root")
		}
		dir = parent
	}
}
