package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
)

const (
	defaultListPage     = 1
	defaultListPageSize = 20
	maxListPageSize     = 200
	telegramBindCodeTTL = 10 * time.Minute
)

var (
	ErrInvalidUserID    = errors.New("invalid user id")
	ErrInvalidUserInput = errors.New("invalid user input")
	ErrSelfBanForbidden = errors.New("admin cannot ban self")
	ErrTelegramIDInUse  = errors.New("telegram id already in use")
)

type CreateUserRequest struct {
	OperatorID       string
	Username         string
	PasswordPlain    string
	Email            *string
	Role             model.UserRole
	Status           model.UserStatus
	TelegramID       *int64
	TelegramUsername *string
	VIPLevel         int
	VIPExpiresAt     *time.Time
	TrafficQuota     int64
	BandwidthLimit   int64
	MaxRules         int
	Permissions      []string
}

type UpdateUserRequest struct {
	OperatorID     string
	Username       *string
	Email          *string
	Role           *model.UserRole
	Status         *model.UserStatus
	VIPLevel       *int
	VIPExpiresAt   *time.Time
	TrafficQuota   *int64
	BandwidthLimit *int64
	MaxRules       *int
	Permissions    *[]string
}

type userListOptions struct {
	status  *model.UserStatus
	role    *model.UserRole
	keyword *string
}

type UserFilter func(*userListOptions)

type UserService struct {
	userRepo  repository.UserRepository
	auditRepo repository.AuditRepository
	bindMu    sync.Mutex
	bindCodes map[string]telegramBindTicket
}

type telegramBindTicket struct {
	TelegramID int64
	Username   string
	ExpiresAt  time.Time
}

func NewUserService(userRepo repository.UserRepository, auditRepo repository.AuditRepository) *UserService {
	return &UserService{
		userRepo:  userRepo,
		auditRepo: auditRepo,
		bindCodes: make(map[string]telegramBindTicket),
	}
}

func ByStatus(status model.UserStatus) UserFilter {
	return func(opts *userListOptions) {
		s := status
		opts.status = &s
	}
}

func ByRole(role model.UserRole) UserFilter {
	return func(opts *userListOptions) {
		r := role
		opts.role = &r
	}
}

func ByKeyword(keyword string) UserFilter {
	return func(opts *userListOptions) {
		trimmed := strings.TrimSpace(keyword)
		if trimmed == "" {
			return
		}
		opts.keyword = &trimmed
	}
}

func (s *UserService) GetByID(ctx context.Context, id string) (*model.User, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, ErrInvalidUserID
	}

	user, err := s.userRepo.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

func (s *UserService) FindByTelegramID(ctx context.Context, telegramID int64) (*model.User, error) {
	if telegramID == 0 {
		return nil, ErrInvalidUserInput
	}

	user, err := s.userRepo.FindByTelegramID(ctx, telegramID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

func (s *UserService) FindByUsername(ctx context.Context, username string) (*model.User, error) {
	name := strings.TrimSpace(username)
	if name == "" {
		return nil, ErrInvalidUserInput
	}

	user, err := s.userRepo.FindByUsername(ctx, name)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return user, nil
}

func (s *UserService) List(ctx context.Context, page, pageSize int, filters ...UserFilter) ([]*model.User, int64, error) {
	normalizedPage, normalizedPageSize := normalizeListPagination(page, pageSize)
	options := &userListOptions{}
	for _, filter := range filters {
		if filter != nil {
			filter(options)
		}
	}

	repoFilter := repository.UserListFilter{
		Role:    options.role,
		Status:  options.status,
		Keyword: options.keyword,
		Pagination: repository.Pagination{
			Limit:  clampIntToInt32(normalizedPageSize),
			Offset: clampIntToInt32((normalizedPage - 1) * normalizedPageSize),
		},
	}

	users, err := s.userRepo.List(ctx, repoFilter)
	if err != nil {
		return nil, 0, err
	}

	total, err := s.userRepo.Count(ctx, repoFilter)
	if err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

func (s *UserService) Create(ctx context.Context, req CreateUserRequest) (*model.User, error) {
	username := strings.TrimSpace(req.Username)
	if username == "" || req.PasswordPlain == "" {
		return nil, ErrInvalidUserInput
	}

	hashed, err := bcrypt.GenerateFromPassword([]byte(req.PasswordPlain), 12)
	if err != nil {
		return nil, err
	}

	role := req.Role
	if role == "" {
		role = model.UserRoleUser
	}

	status := req.Status
	if status == "" {
		status = model.UserStatusNormal
	}

	maxRules := req.MaxRules
	if maxRules <= 0 {
		maxRules = 5
	}

	now := time.Now().UTC()
	user := &model.User{
		ID:               uuid.New(),
		Username:         username,
		PasswordHash:     string(hashed),
		Email:            normalizeStringPointer(req.Email),
		Role:             role,
		Status:           status,
		TelegramID:       req.TelegramID,
		TelegramUsername: normalizeStringPointer(req.TelegramUsername),
		VIPLevel:         req.VIPLevel,
		VIPExpiresAt:     req.VIPExpiresAt,
		TrafficQuota:     req.TrafficQuota,
		TrafficUsed:      0,
		BandwidthLimit:   req.BandwidthLimit,
		MaxRules:         maxRules,
		Permissions:      copyStringSlice(req.Permissions),
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}

	s.writeAudit(ctx, req.OperatorID, "user.create", user.ID.String(), nil, map[string]interface{}{
		"id":       user.ID.String(),
		"username": user.Username,
		"role":     user.Role,
		"status":   user.Status,
	})

	return user, nil
}

func (s *UserService) Update(ctx context.Context, id string, req UpdateUserRequest) (*model.User, error) {
	uid, err := uuid.Parse(id)
	if err != nil {
		return nil, ErrInvalidUserID
	}

	user, err := s.userRepo.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	oldValue, newValue := applyUserUpdate(user, req)
	if len(newValue) == 0 {
		return user, nil
	}

	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, err
	}

	s.writeAudit(ctx, req.OperatorID, "user.update", user.ID.String(), oldValue, newValue)

	return user, nil
}

func (s *UserService) SetStatus(ctx context.Context, operatorID, targetID string, status model.UserStatus) error {
	opID, err := uuid.Parse(operatorID)
	if err != nil {
		return ErrInvalidUserID
	}
	targetUUID, err := uuid.Parse(targetID)
	if err != nil {
		return ErrInvalidUserID
	}

	if opID == targetUUID && status == model.UserStatusBanned {
		return ErrSelfBanForbidden
	}

	targetUser, err := s.userRepo.FindByID(ctx, targetUUID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	if err := s.userRepo.UpdateStatus(ctx, targetUUID, status); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	s.writeAudit(ctx, operatorID, "user.status_change", targetUUID.String(), map[string]interface{}{
		"status": targetUser.Status,
	}, map[string]interface{}{
		"status": status,
	})

	return nil
}

func (s *UserService) BindTelegram(ctx context.Context, userID string, telegramID int64, username string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return ErrInvalidUserID
	}

	existingByTelegram, err := s.userRepo.FindByTelegramID(ctx, telegramID)
	if err == nil && existingByTelegram.ID != uid {
		return ErrTelegramIDInUse
	}
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return err
	}

	user, err := s.userRepo.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	user.TelegramID = &telegramID
	user.TelegramUsername = normalizeStringPointer(&username)

	return s.userRepo.Update(ctx, user)
}

func (s *UserService) GenerateTelegramBindCode(telegramID int64, username string) (string, error) {
	if telegramID == 0 {
		return "", ErrInvalidUserInput
	}

	code, err := generateBindCode()
	if err != nil {
		return "", err
	}

	s.bindMu.Lock()
	defer s.bindMu.Unlock()
	s.pruneExpiredBindCodesLocked()
	s.bindCodes[code] = telegramBindTicket{
		TelegramID: telegramID,
		Username:   strings.TrimSpace(username),
		ExpiresAt:  time.Now().UTC().Add(telegramBindCodeTTL),
	}

	return code, nil
}

func (s *UserService) BindTelegramByCode(ctx context.Context, userID, code string) error {
	normalizedCode := strings.ToUpper(strings.TrimSpace(code))
	if normalizedCode == "" {
		return ErrInvalidUserInput
	}

	s.bindMu.Lock()
	s.pruneExpiredBindCodesLocked()

	ticket, ok := s.bindCodes[normalizedCode]
	if !ok {
		s.bindMu.Unlock()
		return ErrInvalidUserInput
	}
	delete(s.bindCodes, normalizedCode)
	s.bindMu.Unlock()

	return s.BindTelegram(ctx, userID, ticket.TelegramID, ticket.Username)
}

func (s *UserService) UnbindTelegram(ctx context.Context, userID string) error {
	uid, err := uuid.Parse(userID)
	if err != nil {
		return ErrInvalidUserID
	}

	user, err := s.userRepo.FindByID(ctx, uid)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return ErrUserNotFound
		}
		return err
	}

	user.TelegramID = nil
	user.TelegramUsername = nil

	return s.userRepo.Update(ctx, user)
}

func applyUserUpdate(user *model.User, req UpdateUserRequest) (map[string]interface{}, map[string]interface{}) {
	oldValue := make(map[string]interface{})
	newValue := make(map[string]interface{})

	if req.Username != nil {
		username := strings.TrimSpace(*req.Username)
		if username != "" && username != user.Username {
			oldValue["username"] = user.Username
			newValue["username"] = username
			user.Username = username
		}
	}

	if req.Email != nil {
		next := normalizeStringPointer(req.Email)
		if !stringPtrEqual(user.Email, next) {
			oldValue["email"] = ptrValue(user.Email)
			newValue["email"] = ptrValue(next)
			user.Email = next
		}
	}

	if req.Role != nil && user.Role != *req.Role {
		oldValue["role"] = user.Role
		newValue["role"] = *req.Role
		user.Role = *req.Role
	}

	if req.Status != nil && user.Status != *req.Status {
		oldValue["status"] = user.Status
		newValue["status"] = *req.Status
		user.Status = *req.Status
	}

	if req.VIPLevel != nil && user.VIPLevel != *req.VIPLevel {
		oldValue["vip_level"] = user.VIPLevel
		newValue["vip_level"] = *req.VIPLevel
		user.VIPLevel = *req.VIPLevel
	}

	if req.VIPExpiresAt != nil && !timePtrEqual(user.VIPExpiresAt, req.VIPExpiresAt) {
		oldValue["vip_expires_at"] = timePtrValue(user.VIPExpiresAt)
		newValue["vip_expires_at"] = timePtrValue(req.VIPExpiresAt)
		user.VIPExpiresAt = req.VIPExpiresAt
	}

	if req.TrafficQuota != nil && user.TrafficQuota != *req.TrafficQuota {
		oldValue["traffic_quota"] = user.TrafficQuota
		newValue["traffic_quota"] = *req.TrafficQuota
		user.TrafficQuota = *req.TrafficQuota
	}

	if req.BandwidthLimit != nil && user.BandwidthLimit != *req.BandwidthLimit {
		oldValue["bandwidth_limit"] = user.BandwidthLimit
		newValue["bandwidth_limit"] = *req.BandwidthLimit
		user.BandwidthLimit = *req.BandwidthLimit
	}

	if req.MaxRules != nil && user.MaxRules != *req.MaxRules {
		oldValue["max_rules"] = user.MaxRules
		newValue["max_rules"] = *req.MaxRules
		user.MaxRules = *req.MaxRules
	}

	if req.Permissions != nil {
		nextPerms := copyStringSlice(*req.Permissions)
		if !stringSliceEqual(user.Permissions, nextPerms) {
			oldValue["permissions"] = copyStringSlice(user.Permissions)
			newValue["permissions"] = copyStringSlice(nextPerms)
			user.Permissions = nextPerms
		}
	}

	return oldValue, newValue
}

func normalizeListPagination(page, pageSize int) (int, int) {
	if page <= 0 {
		page = defaultListPage
	}
	if pageSize <= 0 {
		pageSize = defaultListPageSize
	}
	if pageSize > maxListPageSize {
		pageSize = maxListPageSize
	}
	return page, pageSize
}

func (s *UserService) writeAudit(
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
		ResourceType: strPtr("user"),
		ResourceID:   strPtr(resourceID),
		OldValue:     oldValue,
		NewValue:     newValue,
		CreatedAt:    time.Now().UTC(),
	})
}

func normalizeStringPointer(v *string) *string {
	if v == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*v)
	if trimmed == "" {
		return nil
	}
	return &trimmed
}

func copyStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringPtrEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func ptrValue(v *string) interface{} {
	if v == nil {
		return nil
	}
	return *v
}

func timePtrEqual(a, b *time.Time) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(*b)
}

func timePtrValue(v *time.Time) interface{} {
	if v == nil {
		return nil
	}
	return v.UTC().Format(time.RFC3339)
}

func (s *UserService) pruneExpiredBindCodesLocked() {
	now := time.Now().UTC()
	for code, ticket := range s.bindCodes {
		if !ticket.ExpiresAt.After(now) {
			delete(s.bindCodes, code)
		}
	}
}

func generateBindCode() (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	code := strings.ToUpper(hex.EncodeToString(buf))
	if len(code) > 8 {
		code = code[:8]
	}
	if len(code) < 6 {
		return "", fmt.Errorf("invalid bind code length: %d", len(code))
	}
	return code, nil
}
