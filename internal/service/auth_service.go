package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
	jwtutil "nodepass-hub/pkg/jwt"
)

const (
	defaultAccessTokenTTL  = 2 * time.Hour
	defaultRefreshTokenTTL = 7 * 24 * time.Hour
	defaultSSOTokenTTL     = 60 * time.Second
)

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrUserBanned          = errors.New("user banned")
	ErrRefreshTokenInvalid = errors.New("refresh token invalid")
	ErrRefreshTokenExpired = errors.New("refresh token expired")
	ErrUserNotFound        = errors.New("user not found")
)

type AuthService struct {
	userRepo   repository.UserRepository
	auditRepo  repository.AuditRepository
	pool       *pgxpool.Pool
	privateKey *rsa.PrivateKey
	accessTTL  time.Duration
	refreshTTL time.Duration
	ssoTTL     time.Duration
}

type TelegramRegistrationOptions struct {
	DefaultTrafficQuota int64
	DefaultMaxRules     int
}

func NewAuthService(
	userRepo repository.UserRepository,
	auditRepo repository.AuditRepository,
	pool *pgxpool.Pool,
	privateKey *rsa.PrivateKey,
) *AuthService {
	return &AuthService{
		userRepo:   userRepo,
		auditRepo:  auditRepo,
		pool:       pool,
		privateKey: privateKey,
		accessTTL:  defaultAccessTokenTTL,
		refreshTTL: defaultRefreshTokenTTL,
		ssoTTL:     defaultSSOTokenTTL,
	}
}

func (s *AuthService) Login(ctx context.Context, username, password string) (accessToken, refreshToken string, err error) {
	if s.privateKey == nil {
		return "", "", errors.New("private key is nil")
	}

	user, err := s.userRepo.FindByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", "", ErrInvalidCredentials
		}
		return "", "", err
	}

	if user.Status == model.UserStatusBanned {
		return "", "", ErrUserBanned
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return "", "", ErrInvalidCredentials
	}

	accessToken, refreshToken, err = s.issueTokensForUser(ctx, user)
	if err != nil {
		return "", "", err
	}

	s.writeAudit(ctx, &user.ID, "user.login")

	return accessToken, refreshToken, nil
}

func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (newAccessToken, newRefreshToken string, err error) {
	if s.privateKey == nil {
		return "", "", errors.New("private key is nil")
	}
	if refreshToken == "" {
		return "", "", ErrRefreshTokenInvalid
	}

	tokenHash := hashToken(refreshToken)

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var userID uuid.UUID
	var role model.UserRole
	var permissions []string
	var status model.UserStatus
	var expiresAt time.Time

	query := `
		SELECT rt.user_id, rt.expires_at, u.role, u.permissions, u.status
		FROM refresh_tokens rt
		JOIN users u ON u.id = rt.user_id
		WHERE rt.token_hash = $1
		FOR UPDATE
	`
	err = tx.QueryRow(ctx, query, tokenHash).Scan(
		&userID,
		&expiresAt,
		&role,
		&permissions,
		&status,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrRefreshTokenInvalid
		}
		return "", "", err
	}

	now := time.Now().UTC()
	if !expiresAt.After(now) {
		if _, delErr := tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE token_hash = $1`, tokenHash); delErr != nil {
			return "", "", delErr
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return "", "", commitErr
		}
		return "", "", ErrRefreshTokenExpired
	}

	if status == model.UserStatusBanned {
		return "", "", ErrUserBanned
	}

	claims := jwtutil.NewClaims(userID.String(), string(role), permissions, s.accessTTL)
	newAccessToken, err = jwtutil.GenerateAccessToken(claims, s.privateKey)
	if err != nil {
		return "", "", err
	}

	newRefreshToken, err = jwtutil.GenerateRefreshToken()
	if err != nil {
		return "", "", err
	}

	newHash := hashToken(newRefreshToken)

	if _, err := tx.Exec(ctx, `DELETE FROM refresh_tokens WHERE token_hash = $1`, tokenHash); err != nil {
		return "", "", err
	}

	if _, err := tx.Exec(
		ctx,
		`INSERT INTO refresh_tokens (token_hash, user_id, expires_at, created_at) VALUES ($1, $2, $3, $4)`,
		newHash,
		userID,
		now.Add(s.refreshTTL),
		now,
	); err != nil {
		return "", "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", "", err
	}

	return newAccessToken, newRefreshToken, nil
}

func (s *AuthService) Logout(ctx context.Context, refreshToken string) error {
	if refreshToken == "" {
		return ErrRefreshTokenInvalid
	}

	tokenHash := hashToken(refreshToken)

	var userID uuid.UUID
	err := s.pool.QueryRow(
		ctx,
		`DELETE FROM refresh_tokens WHERE token_hash = $1 RETURNING user_id`,
		tokenHash,
	).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	}

	s.writeAudit(ctx, &userID, "user.logout")

	return nil
}

func (s *AuthService) ChangePassword(ctx context.Context, userID, oldPwd, newPwd string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return ErrUserNotFound
	}

	user, err := s.userRepo.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPwd)) != nil {
		return ErrInvalidCredentials
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(newPwd), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	user.PasswordHash = string(hashed)
	if err := s.userRepo.Update(ctx, user); err != nil {
		return err
	}

	if _, err := s.pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE user_id = $1`, uid); err != nil {
		return err
	}

	return nil
}

func (s *AuthService) LoginByUserID(ctx context.Context, userID string) (string, string, error) {
	if s.privateKey == nil {
		return "", "", errors.New("private key is nil")
	}

	uid, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return "", "", ErrUserNotFound
	}

	user, err := s.userRepo.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", "", ErrUserNotFound
		}
		return "", "", err
	}
	if user.Status == model.UserStatusBanned {
		return "", "", ErrUserBanned
	}

	accessToken, refreshToken, err := s.issueTokensForUser(ctx, user)
	if err != nil {
		return "", "", err
	}

	s.writeAudit(ctx, &user.ID, "user.login.telegram")
	return accessToken, refreshToken, nil
}

func (s *AuthService) FindByTelegramID(ctx context.Context, telegramID int64) (*model.User, error) {
	user, err := s.userRepo.FindByTelegramID(ctx, telegramID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

func (s *AuthService) CreateTelegramUser(
	ctx context.Context,
	telegramID int64,
	firstName string,
	telegramUsername string,
	opts TelegramRegistrationOptions,
) (*model.User, error) {
	if telegramID == 0 {
		return nil, ErrInvalidUserInput
	}

	maxRules := opts.DefaultMaxRules
	if maxRules <= 0 {
		maxRules = 5
	}
	trafficQuota := opts.DefaultTrafficQuota
	if trafficQuota < 0 {
		trafficQuota = 0
	}

	baseUsername := strings.TrimSpace(telegramUsername)
	if baseUsername == "" {
		baseUsername = buildTelegramUsername(firstName, telegramID)
	}

	passwordSeed, err := jwtutil.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(passwordSeed), 12)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	user := &model.User{
		ID:               uuid.New(),
		Username:         baseUsername,
		PasswordHash:     string(passwordHash),
		Role:             model.UserRoleUser,
		Status:           model.UserStatusNormal,
		TelegramID:       &telegramID,
		TelegramUsername: normalizeStringPointer(&telegramUsername),
		TrafficQuota:     trafficQuota,
		TrafficUsed:      0,
		MaxRules:         maxRules,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	for i := 0; i < 8; i++ {
		if i > 0 {
			user.Username = fmt.Sprintf("%s_%d", baseUsername, i)
		}

		err = s.userRepo.Create(ctx, user)
		if err == nil {
			s.writeAudit(ctx, &user.ID, "user.create.telegram")
			return user, nil
		}

		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
			return nil, err
		}
		if strings.Contains(pgErr.ConstraintName, "users_telegram_id") {
			existing, findErr := s.userRepo.FindByTelegramID(ctx, telegramID)
			if findErr == nil {
				return existing, nil
			}
			if errors.Is(findErr, repository.ErrNotFound) {
				continue
			}
			return nil, findErr
		}
	}

	return nil, errors.New("failed to create telegram user")
}

func (s *AuthService) GenerateSSOToken(ctx context.Context, userID string) (string, error) {
	if s.pool == nil {
		return "", errors.New("database pool is nil")
	}

	uid, err := uuid.Parse(strings.TrimSpace(userID))
	if err != nil {
		return "", ErrInvalidUserID
	}

	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)

	now := time.Now().UTC()
	_, err = s.pool.Exec(
		ctx,
		`INSERT INTO sso_tokens (token, user_id, expires_at, created_at)
		 VALUES ($1, $2, $3, $4)`,
		token,
		uid,
		now.Add(s.ssoTTL),
		now,
	)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (s *AuthService) insertRefreshToken(ctx context.Context, userID uuid.UUID, refreshToken string, ttl time.Duration) error {
	now := time.Now().UTC()
	_, err := s.pool.Exec(
		ctx,
		`INSERT INTO refresh_tokens (token_hash, user_id, expires_at, created_at) VALUES ($1, $2, $3, $4)`,
		hashToken(refreshToken),
		userID,
		now.Add(ttl),
		now,
	)
	return err
}

func (s *AuthService) issueTokensForUser(ctx context.Context, user *model.User) (string, string, error) {
	if user == nil {
		return "", "", ErrUserNotFound
	}
	claims := jwtutil.NewClaims(user.ID.String(), string(user.Role), user.Permissions, s.accessTTL)
	accessToken, err := jwtutil.GenerateAccessToken(claims, s.privateKey)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := jwtutil.GenerateRefreshToken()
	if err != nil {
		return "", "", err
	}

	if err := s.insertRefreshToken(ctx, user.ID, refreshToken, s.refreshTTL); err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

func (s *AuthService) writeAudit(ctx context.Context, userID *uuid.UUID, action string) {
	if s.auditRepo == nil {
		return
	}

	_ = s.auditRepo.Create(ctx, &model.AuditLog{
		UserID:       userID,
		Action:       action,
		ResourceType: strPtr("user"),
		ResourceID:   uuidToStringPtr(userID),
		CreatedAt:    time.Now().UTC(),
	})
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func strPtr(v string) *string {
	return &v
}

func uuidToStringPtr(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	v := id.String()
	return &v
}

func buildTelegramUsername(firstName string, telegramID int64) string {
	clean := strings.TrimSpace(firstName)
	if clean == "" {
		return fmt.Sprintf("tg_%d", telegramID)
	}

	var b strings.Builder
	for _, r := range strings.ToLower(clean) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
		if b.Len() >= 24 {
			break
		}
	}

	base := b.String()
	if base == "" {
		return fmt.Sprintf("tg_%d", telegramID)
	}
	return fmt.Sprintf("tg_%s", base)
}
