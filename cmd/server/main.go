// @title NodePass Hub API
// @version 1.0
// @description NodePass Hub service API documentation.
// @BasePath /
// @schemes http https
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	jwt "github.com/golang-jwt/jwt/v5"
	migrate "github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/viper"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	swaggerdocs "nodepass-hub/docs/swagger"
	"nodepass-hub/internal/api"
	"nodepass-hub/internal/api/middleware"
	v1 "nodepass-hub/internal/api/v1"
	"nodepass-hub/internal/event"
	hubpkg "nodepass-hub/internal/hub"
	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
	"nodepass-hub/internal/repository/postgres"
	"nodepass-hub/internal/scheduler"
	"nodepass-hub/internal/service"
	"nodepass-hub/internal/sse"
	systemlog "nodepass-hub/pkg/logger"
)

type Config struct {
	App struct {
		Env string `mapstructure:"env"`
	} `mapstructure:"app"`
	Server struct {
		Host            string        `mapstructure:"host"`
		Port            int           `mapstructure:"port"`
		ReadTimeout     time.Duration `mapstructure:"read_timeout"`
		WriteTimeout    time.Duration `mapstructure:"write_timeout"`
		ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	} `mapstructure:"server"`
	Database struct {
		URL         string        `mapstructure:"url"`
		MaxConns    int           `mapstructure:"max_conns"`
		PingTimeout time.Duration `mapstructure:"ping_timeout"`
	} `mapstructure:"database"`
	Log struct {
		Level    string `mapstructure:"level"`
		Encoding string `mapstructure:"encoding"`
	} `mapstructure:"log"`
	Security struct {
		AgentHMACSecret     string `mapstructure:"agent_hmac_secret"`
		AgentHMACSecretFile string `mapstructure:"agent_hmac_secret_file"`
	} `mapstructure:"security"`
	CORS struct {
		AllowOrigins []string `mapstructure:"allow_origins"`
	} `mapstructure:"cors"`
	Debug struct {
		PprofEnabled bool `mapstructure:"pprof_enabled"`
	} `mapstructure:"debug"`
}

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			os.Exit(runHealthcheck())
		case "migrate":
			if err := runMigrateCommand(); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			return
		case "create-admin":
			if err := runCreateAdminCommand(os.Args[2:]); err != nil {
				fmt.Fprintln(os.Stderr, err.Error())
				os.Exit(1)
			}
			return
		}
	}

	cfg, err := loadConfig()
	if err != nil {
		panic(fmt.Errorf("load config: %w", err))
	}

	logger, systemLogStore, err := newLogger(cfg)
	if err != nil {
		panic(fmt.Errorf("init logger: %w", err))
	}
	defer logger.Sync() //nolint:errcheck

	isDebugMode := strings.EqualFold(cfg.App.Env, "development")
	if !isDebugMode {
		gin.SetMode(gin.ReleaseMode)
	}

	dbPool, err := newDBPool(context.Background(), cfg)
	if err != nil {
		logger.Fatal("connect database failed", zap.Error(err))
	}
	defer dbPool.Close()

	userRepo := postgres.NewUserRepository(dbPool)
	nodeRepo := postgres.NewNodeRepository(dbPool)
	ruleRepo := postgres.NewRuleRepository(dbPool)
	trafficRepo := postgres.NewTrafficRepository(dbPool)
	auditRepo := postgres.NewAuditRepository(dbPool)
	benefitCodeRepo := postgres.NewBenefitCodeRepository(dbPool)

	sseHub := sse.NewHub(logger)
	defer sseHub.Close()

	eventBus := event.NewBus()
	trafficSvc := service.NewTrafficService(trafficRepo, userRepo, ruleRepo, auditRepo, dbPool, eventBus, logger)
	hub := hubpkg.NewHub(nodeRepo, trafficSvc, sseHub, eventBus, logger)
	defer hub.Close()

	nodeSvc := service.NewNodeService(nodeRepo, auditRepo, sseHub, dbPool, service.NodeServiceConfig{
		HMACSecret: cfg.Security.AgentHMACSecret,
	}, logger)
	lbSvc := service.NewLBService(dbPool, nodeRepo, hub, sseHub, logger)
	defer lbSvc.Close()
	hopChainSvc := service.NewHopChainService(dbPool, ruleRepo, nodeRepo, hub, logger)
	ruleSvc := service.NewRuleService(
		ruleRepo,
		userRepo,
		nodeRepo,
		auditRepo,
		dbPool,
		hub,
		sseHub,
		lbSvc,
		hopChainSvc,
		nodeSvc,
		logger,
	)
	vipSvc := service.NewVIPService(userRepo, auditRepo, dbPool, ruleSvc, eventBus, sseHub, logger)
	codeSvc := service.NewBenefitCodeService(benefitCodeRepo, auditRepo, dbPool, vipSvc, sseHub, logger)
	auditSvc := service.NewAuditService(auditRepo, dbPool)
	systemSvc := service.NewSystemService(dbPool, auditRepo, sseHub, logger)
	announcementSvc := service.NewAnnouncementService(dbPool, auditRepo, sseHub, logger)
	userSvc := service.NewUserService(userRepo, auditRepo)
	notificationSvc := service.NewNotificationService(userRepo, systemSvc, dbPool, logger)
	policySvc := service.NewPolicyService(dbPool, ruleSvc, trafficSvc, logger)

	jwtPrivateKey, err := loadRSAPrivateKey()
	if err != nil {
		logger.Fatal("load jwt private key failed", zap.Error(err))
	}
	authSvc := service.NewAuthService(userRepo, auditRepo, dbPool, jwtPrivateKey)

	registerQuotaExceededSubscriber(eventBus, ruleSvc, sseHub, auditRepo, logger)
	registerNotificationSubscribers(eventBus, notificationSvc, logger)
	middleware.SetAuditRepository(auditRepo)
	if _, err := systemSvc.GetConfig(context.Background()); err != nil {
		logger.Warn("load system config failed", zap.Error(err))
	}

	vipExpiryJob := scheduler.NewVIPExpiryJob(vipSvc, logger)
	if err := vipExpiryJob.Start(); err != nil {
		logger.Fatal("start vip expiry job failed", zap.Error(err))
	}
	defer vipExpiryJob.Stop()

	policyJob := scheduler.NewPolicyJob(policySvc, logger)
	if err := policyJob.Start(); err != nil {
		logger.Fatal("start policy job failed", zap.Error(err))
	}
	defer policyJob.Stop()

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(buildCORSMiddleware(cfg))
	router.Use(middleware.RequestLogger(logger))

	healthHandler := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
	readyHandler := func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), cfg.Database.PingTimeout)
		defer cancel()

		if err := dbPool.Ping(ctx); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"status": "not_ready",
				"error":  "database unavailable",
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	}

	router.GET("/health", healthHandler)
	router.GET("/health/ready", readyHandler)
	router.GET("/api/v1/health", healthHandler)
	router.GET("/api/v1/health/ready", readyHandler)

	if isDebugMode && cfg.Debug.PprofEnabled {
		router.Any("/debug/pprof/*path", gin.WrapH(http.DefaultServeMux))
		logger.Info("pprof endpoint enabled", zap.String("path", "/debug/pprof/"))
	}
	if shouldEnableSwaggerDocs(cfg.App.Env) {
		swaggerdocs.SwaggerInfo.BasePath = "/"
		router.GET("/docs/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	apiV1 := router.Group("/api/v1")
	apiV1.Use(middleware.MaintenanceMode())
	v1.RegisterAuthRoutes(apiV1, authSvc, systemSvc)
	v1.RegisterUserRoutes(apiV1, userSvc)
	v1.RegisterTelegramWebhookRoute(apiV1, userSvc, systemSvc, notificationSvc, logger)
	v1.RegisterTrafficRoutes(apiV1, trafficSvc, ruleSvc)
	v1.RegisterAuditRoutes(apiV1, auditSvc)
	v1.RegisterSystemRoutes(apiV1, systemSvc, systemLogStore)
	v1.RegisterAnnouncementRoutes(apiV1, announcementSvc)
	v1.RegisterLBGroupRoutes(apiV1, lbSvc)
	v1.RegisterHopChainRoutes(apiV1, hopChainSvc)
	v1.RegisterVIPRoutes(apiV1, vipSvc)
	v1.RegisterCodeRoutes(apiV1, codeSvc)
	v1.RegisterNodeRoutes(apiV1, nodeSvc)
	v1.RegisterRuleRoutes(apiV1, ruleSvc)
	v1.RegisterSSERoutes(apiV1, sseHub)
	v1.RegisterWSRoutes(router, hub, cfg.Security.AgentHMACSecret)
	api.RegisterExternalRoutes(router, dbPool, userSvc, vipSvc, ruleSvc, auditRepo, logger)
	api.RegisterInternalRoutes(router, nodeSvc, trafficSvc, policySvc, cfg.Security.AgentHMACSecret)

	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}

	serverErrCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrCh <- err
			return
		}
		serverErrCh <- nil
	}()

	logger.Info("server started",
		zap.String("addr", srv.Addr),
		zap.String("version", Version),
		zap.String("commit", Commit),
		zap.String("build_time", BuildTime),
	)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", zap.String("signal", sig.String()))
	case err := <-serverErrCh:
		if err != nil {
			logger.Fatal("server exited unexpectedly", zap.Error(err))
		}
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown server failed", zap.Error(err))
	}
}

func loadConfig() (Config, error) {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")

	v.SetEnvPrefix("NODEPASS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("app.env", "development")
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", "10s")
	v.SetDefault("server.write_timeout", "15s")
	v.SetDefault("server.shutdown_timeout", "10s")
	v.SetDefault("database.max_conns", 10)
	v.SetDefault("database.ping_timeout", "3s")
	v.SetDefault("log.level", "info")
	v.SetDefault("log.encoding", "json")
	v.SetDefault("security.agent_hmac_secret", "")
	v.SetDefault("security.agent_hmac_secret_file", "")
	v.SetDefault("cors.allow_origins", []string{"http://localhost:5173"})
	v.SetDefault("debug.pprof_enabled", false)

	if err := v.ReadInConfig(); err != nil {
		var notFoundErr viper.ConfigFileNotFoundError
		if !errors.As(err, &notFoundErr) {
			return Config{}, fmt.Errorf("read config file failed: %w", err)
		}
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config failed: %w", err)
	}

	if strings.TrimSpace(cfg.Security.AgentHMACSecret) == "" && strings.TrimSpace(cfg.Security.AgentHMACSecretFile) != "" {
		raw, err := os.ReadFile(strings.TrimSpace(cfg.Security.AgentHMACSecretFile))
		if err != nil {
			return Config{}, fmt.Errorf("read security.agent_hmac_secret_file failed: %w", err)
		}
		cfg.Security.AgentHMACSecret = strings.TrimSpace(string(raw))
	}

	if cfg.Database.URL == "" {
		return Config{}, errors.New("database.url is required")
	}

	if cfg.Database.MaxConns <= 0 {
		return Config{}, errors.New("database.max_conns must be greater than 0")
	}

	if cfg.Database.PingTimeout <= 0 {
		return Config{}, errors.New("database.ping_timeout must be greater than 0")
	}

	if len(cfg.CORS.AllowOrigins) == 0 {
		return Config{}, errors.New("cors.allow_origins must not be empty")
	}
	for _, origin := range cfg.CORS.AllowOrigins {
		if strings.TrimSpace(origin) == "*" {
			return Config{}, errors.New("cors.allow_origins must not contain wildcard *")
		}
	}

	return cfg, nil
}

func newLogger(cfg Config) (*zap.Logger, *systemlog.SystemLogStore, error) {
	var zapCfg zap.Config
	if strings.EqualFold(cfg.App.Env, "development") {
		zapCfg = zap.NewDevelopmentConfig()
	} else {
		zapCfg = zap.NewProductionConfig()
	}

	if cfg.Log.Level != "" {
		if err := zapCfg.Level.UnmarshalText([]byte(cfg.Log.Level)); err != nil {
			return nil, nil, fmt.Errorf("invalid log.level: %w", err)
		}
	}

	if cfg.Log.Encoding != "" {
		zapCfg.Encoding = cfg.Log.Encoding
	}

	logger, err := zapCfg.Build()
	if err != nil {
		return nil, nil, fmt.Errorf("build zap logger failed: %w", err)
	}

	logStore := systemlog.NewSystemLogStore(1000)
	logger = systemlog.WrapZapLogger(logger, logStore)
	return logger, logStore, nil
}

func newDBPool(ctx context.Context, cfg Config) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.Database.URL)
	if err != nil {
		return nil, fmt.Errorf("parse database.url failed: %w", err)
	}

	poolCfg.MaxConns = int32(cfg.Database.MaxConns)

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create pgx pool failed: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.Database.PingTimeout)
	defer cancel()

	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database failed: %w", err)
	}

	return pool, nil
}

func buildCORSMiddleware(cfg Config) gin.HandlerFunc {
	origins := make([]string, 0, len(cfg.CORS.AllowOrigins))
	for _, origin := range cfg.CORS.AllowOrigins {
		trimmed := strings.TrimSpace(origin)
		if trimmed == "" {
			continue
		}
		origins = append(origins, trimmed)
	}
	if len(origins) == 0 {
		origins = []string{"http://localhost:5173"}
	}

	return cors.New(cors.Config{
		AllowOrigins:     origins,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Type"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	})
}

func shouldEnableSwaggerDocs(env string) bool {
	switch strings.ToLower(strings.TrimSpace(env)) {
	case "development", "staging":
		return true
	default:
		return false
	}
}

func registerQuotaExceededSubscriber(
	bus *event.Bus,
	ruleSvc *service.RuleService,
	sseHub *sse.SSEHub,
	auditRepo repository.AuditRepository,
	logger *zap.Logger,
) {
	if bus == nil {
		return
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	bus.Subscribe(event.EventUserQuotaExceeded, func(payload any) {
		quotaPayload, ok := normalizeQuotaPayload(payload)
		if !ok || strings.TrimSpace(quotaPayload.UserID) == "" {
			return
		}

		userID := strings.TrimSpace(quotaPayload.UserID)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		if ruleSvc != nil {
			if err := ruleSvc.PauseAllUserRules(ctx, userID); err != nil {
				logger.Warn("pause all user rules failed after quota exceeded",
					zap.String("user_id", userID),
					zap.Error(err),
				)
			}
		}

		if sseHub != nil {
			sseHub.SendToUser(userID, sse.NewEvent(sse.EventTrafficUpdate, map[string]interface{}{
				"user_id":       userID,
				"traffic_used":  quotaPayload.TrafficUsed,
				"traffic_quota": quotaPayload.TrafficQuota,
				"status":        "quota_exceeded",
				"ts":            time.Now().UTC().Format(time.RFC3339Nano),
			}))
		}

		logger.Info("quota exceeded event received, telegram notification pending implementation",
			zap.String("user_id", userID),
		)

		if auditRepo != nil {
			var actorID *uuid.UUID
			if parsed, err := uuid.Parse(userID); err == nil {
				actorID = &parsed
			}
			_ = auditRepo.Create(ctx, &model.AuditLog{
				UserID:       actorID,
				Action:       "user.quota.exceeded",
				ResourceType: strPtr("user"),
				ResourceID:   strPtr(userID),
				NewValue: map[string]interface{}{
					"traffic_used":  quotaPayload.TrafficUsed,
					"traffic_quota": quotaPayload.TrafficQuota,
				},
				CreatedAt: time.Now().UTC(),
			})
		}
	})
}

func normalizeQuotaPayload(payload any) (event.QuotaExceededPayload, bool) {
	switch data := payload.(type) {
	case event.QuotaExceededPayload:
		return data, true
	case *event.QuotaExceededPayload:
		if data == nil {
			return event.QuotaExceededPayload{}, false
		}
		return *data, true
	case map[string]interface{}:
		userIDAny, ok := data["user_id"]
		if !ok {
			return event.QuotaExceededPayload{}, false
		}
		userID, _ := userIDAny.(string)

		used := int64(0)
		quota := int64(0)
		if usedAny, ok := data["traffic_used"]; ok {
			switch v := usedAny.(type) {
			case float64:
				used = int64(v)
			case int64:
				used = v
			case int:
				used = int64(v)
			}
		}
		if quotaAny, ok := data["traffic_quota"]; ok {
			switch v := quotaAny.(type) {
			case float64:
				quota = int64(v)
			case int64:
				quota = v
			case int:
				quota = int64(v)
			}
		}

		return event.QuotaExceededPayload{
			UserID:       userID,
			TrafficUsed:  used,
			TrafficQuota: quota,
		}, true
	default:
		return event.QuotaExceededPayload{}, false
	}
}

func strPtr(v string) *string {
	return &v
}

func loadRSAPrivateKey() (*rsa.PrivateKey, error) {
	pem := strings.TrimSpace(os.Getenv("NODEPASS_JWT_PRIVATE_KEY"))
	if pem == "" {
		path := strings.TrimSpace(os.Getenv("NODEPASS_JWT_PRIVATE_KEY_FILE"))
		if path != "" {
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			pem = string(raw)
		}
	}
	if pem == "" {
		return nil, errors.New("jwt private key not configured")
	}
	return jwt.ParseRSAPrivateKeyFromPEM([]byte(pem))
}

func registerNotificationSubscribers(
	bus *event.Bus,
	notificationSvc *service.NotificationService,
	logger *zap.Logger,
) {
	if bus == nil || notificationSvc == nil {
		return
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	bus.Subscribe(event.EventUserQuotaExceeded, func(payload any) {
		quota, ok := normalizeQuotaPayload(payload)
		if !ok {
			return
		}

		_ = notificationSvc.SendToUser(context.Background(), quota.UserID, service.NotificationQuotaExceeded, map[string]string{
			"traffic_used":  fmt.Sprintf("%d", quota.TrafficUsed),
			"traffic_quota": fmt.Sprintf("%d", quota.TrafficQuota),
		})
	})

	bus.Subscribe(event.EventUserVIPExpired, func(payload any) {
		vipPayload, ok := normalizeVIPExpiredPayload(payload)
		if !ok || strings.TrimSpace(vipPayload.UserID) == "" {
			return
		}

		_ = notificationSvc.SendToUser(context.Background(), vipPayload.UserID, service.NotificationVIPWarning1D, map[string]string{
			"days":       "0",
			"expires_at": "已到期",
		})
	})

	bus.Subscribe(event.EventNodeOffline, func(payload any) {
		nodePayload, ok := normalizeNodeOfflinePayload(payload)
		if !ok || strings.TrimSpace(nodePayload.NodeID) == "" {
			return
		}

		_ = notificationSvc.SendToAdmins(context.Background(), service.NotificationNodeOffline, map[string]string{
			"node_id":     nodePayload.NodeID,
			"timestamp":   nodePayload.Timestamp.UTC().Format(time.RFC3339Nano),
			"agent_id":    nodePayload.NodeID,
			"occurred_at": nodePayload.Timestamp.UTC().Format(time.RFC3339Nano),
		})
	})
}

func normalizeVIPExpiredPayload(payload any) (event.VIPExpiredPayload, bool) {
	switch data := payload.(type) {
	case event.VIPExpiredPayload:
		return data, true
	case *event.VIPExpiredPayload:
		if data == nil {
			return event.VIPExpiredPayload{}, false
		}
		return *data, true
	case map[string]interface{}:
		userID, _ := data["user_id"].(string)
		return event.VIPExpiredPayload{UserID: userID}, strings.TrimSpace(userID) != ""
	default:
		return event.VIPExpiredPayload{}, false
	}
}

func normalizeNodeOfflinePayload(payload any) (event.NodeOfflinePayload, bool) {
	switch data := payload.(type) {
	case event.NodeOfflinePayload:
		if data.Timestamp.IsZero() {
			data.Timestamp = time.Now().UTC()
		}
		return data, strings.TrimSpace(data.NodeID) != ""
	case *event.NodeOfflinePayload:
		if data == nil {
			return event.NodeOfflinePayload{}, false
		}
		value := *data
		if value.Timestamp.IsZero() {
			value.Timestamp = time.Now().UTC()
		}
		return value, strings.TrimSpace(value.NodeID) != ""
	case map[string]interface{}:
		nodeID, _ := data["node_id"].(string)
		if nodeID == "" {
			nodeID, _ = data["agent_id"].(string)
		}
		ts := time.Now().UTC()
		if rawTS, ok := data["timestamp"]; ok {
			switch v := rawTS.(type) {
			case time.Time:
				ts = v.UTC()
			case string:
				if parsed, err := time.Parse(time.RFC3339Nano, v); err == nil {
					ts = parsed.UTC()
				}
			}
		}
		return event.NodeOfflinePayload{
			NodeID:    strings.TrimSpace(nodeID),
			Timestamp: ts,
		}, strings.TrimSpace(nodeID) != ""
	default:
		return event.NodeOfflinePayload{}, false
	}
}

func runMigrateCommand() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config failed: %w", err)
	}

	migrationSource := "file:///migrations"
	if _, statErr := os.Stat("/migrations"); statErr != nil {
		migrationSource = "file://./migrations"
	}

	migrator, err := migrate.New(migrationSource, cfg.Database.URL)
	if err != nil {
		return fmt.Errorf("init migrator failed: %w", err)
	}
	defer migrator.Close() //nolint:errcheck

	if err := migrator.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("run migrations failed: %w", err)
	}

	fmt.Println("migrations applied successfully")
	return nil
}

func runCreateAdminCommand(args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("load config failed: %w", err)
	}

	fs := flag.NewFlagSet("create-admin", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var username string
	var password string
	var email string

	fs.StringVar(&username, "username", "admin", "admin username")
	fs.StringVar(&password, "password", "", "admin password")
	fs.StringVar(&email, "email", "", "admin email")

	if err := fs.Parse(args); err != nil {
		return err
	}

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username is required")
	}
	if !isStrongPassword(password) {
		return errors.New("password must be >=12 chars and include upper/lowercase letters and digits")
	}
	if strings.TrimSpace(email) != "" && !isValidEmail(email) {
		return errors.New("invalid email format")
	}

	poolCfg, err := pgxpool.ParseConfig(cfg.Database.URL)
	if err != nil {
		return fmt.Errorf("parse database config failed: %w", err)
	}
	poolCfg.MaxConns = 2

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return fmt.Errorf("connect database failed: %w", err)
	}
	defer pool.Close()

	var existingID uuid.UUID
	err = pool.QueryRow(ctx, `SELECT id FROM users WHERE username = $1`, username).Scan(&existingID)
	if err == nil {
		fmt.Printf("admin user '%s' already exists, skip\n", username)
		return nil
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("query admin user failed: %w", err)
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return fmt.Errorf("hash password failed: %w", err)
	}

	var emailPtr *string
	if strings.TrimSpace(email) != "" {
		trimmed := strings.TrimSpace(email)
		emailPtr = &trimmed
	}

	_, err = pool.Exec(
		ctx,
		`INSERT INTO users (
			id, username, password_hash, email, role, status,
			traffic_quota, traffic_used, bandwidth_limit, max_rules,
			created_at, updated_at
		) VALUES (
			gen_random_uuid(), $1, $2, $3, 'admin', 'normal',
			0, 0, 0, 100,
			NOW(), NOW()
		)`,
		username,
		string(hashed),
		emailPtr,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			fmt.Printf("admin user '%s' already exists, skip\n", username)
			return nil
		}
		return fmt.Errorf("create admin failed: %w", err)
	}

	fmt.Printf("admin user '%s' created successfully\n", username)
	return nil
}

func isStrongPassword(password string) bool {
	if len(password) < 12 {
		return false
	}
	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	return hasLower && hasUpper && hasDigit
}

func isValidEmail(email string) bool {
	trimmed := strings.TrimSpace(email)
	if trimmed == "" {
		return true
	}
	return regexp.MustCompile(`^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$`).MatchString(trimmed)
}

func runHealthcheck() int {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("http://localhost:8080/health/ready")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 1
	}
	return 0
}
