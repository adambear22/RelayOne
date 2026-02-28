package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"nodepass-hub/internal/model"
	"nodepass-hub/internal/repository"
	"nodepass-hub/internal/sse"
)

const (
	announcementListDefaultPage = 1
	announcementListDefaultSize = 20
	announcementListMaxPageSize = 200
)

const announcementColumns = `
	id,
	type,
	title,
	content,
	is_enabled,
	starts_at,
	ends_at,
	created_by,
	created_at
`

var (
	ErrAnnouncementNotFound   = errors.New("announcement not found")
	ErrInvalidAnnouncementReq = errors.New("invalid announcement input")
)

type CreateAnnouncementRequest struct {
	Type      string     `json:"type"`
	Title     string     `json:"title"`
	Content   string     `json:"content"`
	IsEnabled *bool      `json:"is_enabled,omitempty"`
	StartsAt  *time.Time `json:"starts_at,omitempty"`
	EndsAt    *time.Time `json:"ends_at,omitempty"`
}

type UpdateAnnouncementRequest struct {
	Type      *string    `json:"type,omitempty"`
	Title     *string    `json:"title,omitempty"`
	Content   *string    `json:"content,omitempty"`
	IsEnabled *bool      `json:"is_enabled,omitempty"`
	StartsAt  *time.Time `json:"starts_at,omitempty"`
	EndsAt    *time.Time `json:"ends_at,omitempty"`
}

type AnnouncementService struct {
	pool      *pgxpool.Pool
	auditRepo repository.AuditRepository
	sseHub    *sse.SSEHub
	logger    *zap.Logger
}

func NewAnnouncementService(
	pool *pgxpool.Pool,
	auditRepo repository.AuditRepository,
	sseHub *sse.SSEHub,
	logger *zap.Logger,
) *AnnouncementService {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &AnnouncementService{
		pool:      pool,
		auditRepo: auditRepo,
		sseHub:    sseHub,
		logger:    logger,
	}
}

func (s *AnnouncementService) Create(
	ctx context.Context,
	operatorID string,
	req CreateAnnouncementRequest,
) (*model.Announcement, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	operatorUUID, err := uuid.Parse(strings.TrimSpace(operatorID))
	if err != nil {
		return nil, ErrInvalidUserID
	}

	announcement, err := buildAnnouncementForCreate(operatorUUID, req)
	if err != nil {
		return nil, err
	}

	_, err = s.pool.Exec(
		ctx,
		`INSERT INTO announcements (
			id, type, title, content, is_enabled, starts_at, ends_at, created_by, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		announcement.ID,
		announcement.Type,
		announcement.Title,
		announcement.Content,
		announcement.IsEnabled,
		announcement.StartsAt,
		announcement.EndsAt,
		announcement.CreatedBy,
		announcement.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	s.writeAudit(ctx, &operatorUUID, "announcement.create", announcement.ID.String(), nil, map[string]interface{}{
		"type":       announcement.Type,
		"title":      announcement.Title,
		"is_enabled": announcement.IsEnabled,
		"starts_at":  formatTimePtr(announcement.StartsAt),
		"ends_at":    formatTimePtr(announcement.EndsAt),
	})
	s.broadcast("create", announcement)

	return announcement, nil
}

func (s *AnnouncementService) Update(
	ctx context.Context,
	operatorID string,
	announcementID string,
	req UpdateAnnouncementRequest,
) (*model.Announcement, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	operatorUUID, err := uuid.Parse(strings.TrimSpace(operatorID))
	if err != nil {
		return nil, ErrInvalidUserID
	}
	id, err := uuid.Parse(strings.TrimSpace(announcementID))
	if err != nil {
		return nil, ErrInvalidAnnouncementReq
	}

	current, err := s.getByUUID(ctx, id)
	if err != nil {
		return nil, err
	}

	next, err := buildAnnouncementForUpdate(current, req)
	if err != nil {
		return nil, err
	}

	tag, err := s.pool.Exec(
		ctx,
		`UPDATE announcements
		    SET type = $2,
		        title = $3,
		        content = $4,
		        is_enabled = $5,
		        starts_at = $6,
		        ends_at = $7
		  WHERE id = $1`,
		next.ID,
		next.Type,
		next.Title,
		next.Content,
		next.IsEnabled,
		next.StartsAt,
		next.EndsAt,
	)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrAnnouncementNotFound
	}

	s.writeAudit(ctx, &operatorUUID, "announcement.update", next.ID.String(), map[string]interface{}{
		"type":       current.Type,
		"title":      current.Title,
		"content":    current.Content,
		"is_enabled": current.IsEnabled,
		"starts_at":  formatTimePtr(current.StartsAt),
		"ends_at":    formatTimePtr(current.EndsAt),
	}, map[string]interface{}{
		"type":       next.Type,
		"title":      next.Title,
		"content":    next.Content,
		"is_enabled": next.IsEnabled,
		"starts_at":  formatTimePtr(next.StartsAt),
		"ends_at":    formatTimePtr(next.EndsAt),
	})
	s.broadcast("update", next)

	return next, nil
}

func (s *AnnouncementService) Delete(ctx context.Context, operatorID string, announcementID string) error {
	if s.pool == nil {
		return errors.New("database pool is nil")
	}

	operatorUUID, err := uuid.Parse(strings.TrimSpace(operatorID))
	if err != nil {
		return ErrInvalidUserID
	}
	id, err := uuid.Parse(strings.TrimSpace(announcementID))
	if err != nil {
		return ErrInvalidAnnouncementReq
	}

	current, err := s.getByUUID(ctx, id)
	if err != nil {
		return err
	}

	tag, err := s.pool.Exec(ctx, `DELETE FROM announcements WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrAnnouncementNotFound
	}

	s.writeAudit(ctx, &operatorUUID, "announcement.delete", id.String(), map[string]interface{}{
		"type":       current.Type,
		"title":      current.Title,
		"is_enabled": current.IsEnabled,
		"starts_at":  formatTimePtr(current.StartsAt),
		"ends_at":    formatTimePtr(current.EndsAt),
	}, nil)

	if s.sseHub != nil {
		s.sseHub.Broadcast(sse.NewEvent(sse.EventAnnouncement, map[string]interface{}{
			"action": "delete",
			"id":     id.String(),
			"ts":     time.Now().UTC().Format(time.RFC3339Nano),
		}))
	}

	return nil
}

func (s *AnnouncementService) Toggle(
	ctx context.Context,
	operatorID string,
	announcementID string,
	enabled bool,
) (*model.Announcement, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	operatorUUID, err := uuid.Parse(strings.TrimSpace(operatorID))
	if err != nil {
		return nil, ErrInvalidUserID
	}
	id, err := uuid.Parse(strings.TrimSpace(announcementID))
	if err != nil {
		return nil, ErrInvalidAnnouncementReq
	}

	current, err := s.getByUUID(ctx, id)
	if err != nil {
		return nil, err
	}

	tag, err := s.pool.Exec(
		ctx,
		`UPDATE announcements
		    SET is_enabled = $2
		  WHERE id = $1`,
		id,
		enabled,
	)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrAnnouncementNotFound
	}

	item, err := s.getByUUID(ctx, id)
	if err != nil {
		return nil, err
	}

	s.writeAudit(ctx, &operatorUUID, "announcement.toggle", id.String(), map[string]interface{}{
		"is_enabled": current.IsEnabled,
	}, map[string]interface{}{
		"is_enabled": enabled,
	})
	s.broadcast("toggle", item)
	return item, nil
}

func (s *AnnouncementService) GetByID(ctx context.Context, announcementID string) (*model.Announcement, error) {
	id, err := uuid.Parse(strings.TrimSpace(announcementID))
	if err != nil {
		return nil, ErrInvalidAnnouncementReq
	}
	return s.getByUUID(ctx, id)
}

func (s *AnnouncementService) List(
	ctx context.Context,
	page, pageSize int,
) ([]*model.Announcement, int64, error) {
	if s.pool == nil {
		return nil, 0, errors.New("database pool is nil")
	}

	page, pageSize = normalizeAnnouncementPagination(page, pageSize)

	rows, err := s.pool.Query(
		ctx,
		`SELECT `+announcementColumns+`
		   FROM announcements
		  ORDER BY created_at DESC
		  LIMIT $1 OFFSET $2`,
		pageSize,
		(page-1)*pageSize,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	items := make([]*model.Announcement, 0, pageSize)
	for rows.Next() {
		item, scanErr := scanAnnouncement(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var total int64
	if err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM announcements`).Scan(&total); err != nil {
		return nil, 0, err
	}

	return items, total, nil
}

func (s *AnnouncementService) ListActive(ctx context.Context) ([]*model.Announcement, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	rows, err := s.pool.Query(
		ctx,
		`SELECT `+announcementColumns+`
		   FROM announcements
		  WHERE is_enabled = TRUE
		    AND (starts_at IS NULL OR starts_at <= NOW())
		    AND (ends_at IS NULL OR ends_at > NOW())
		  ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]*model.Announcement, 0, 16)
	for rows.Next() {
		item, scanErr := scanAnnouncement(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return items, nil
}

func (s *AnnouncementService) getByUUID(ctx context.Context, id uuid.UUID) (*model.Announcement, error) {
	if s.pool == nil {
		return nil, errors.New("database pool is nil")
	}

	row := s.pool.QueryRow(ctx, `SELECT `+announcementColumns+` FROM announcements WHERE id = $1`, id)
	item, err := scanAnnouncement(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrAnnouncementNotFound
		}
		return nil, err
	}
	return item, nil
}

func buildAnnouncementForCreate(operatorID uuid.UUID, req CreateAnnouncementRequest) (*model.Announcement, error) {
	typ := strings.TrimSpace(req.Type)
	title := strings.TrimSpace(req.Title)
	content := strings.TrimSpace(req.Content)
	if typ == "" || title == "" || content == "" {
		return nil, ErrInvalidAnnouncementReq
	}

	enabled := true
	if req.IsEnabled != nil {
		enabled = *req.IsEnabled
	}

	startsAt := cloneTimePtr(req.StartsAt)
	endsAt := cloneTimePtr(req.EndsAt)
	if !isAnnouncementWindowValid(startsAt, endsAt) {
		return nil, ErrInvalidAnnouncementReq
	}

	return &model.Announcement{
		ID:        uuid.New(),
		Type:      typ,
		Title:     title,
		Content:   content,
		IsEnabled: enabled,
		StartsAt:  startsAt,
		EndsAt:    endsAt,
		CreatedBy: operatorID,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func buildAnnouncementForUpdate(
	current *model.Announcement,
	req UpdateAnnouncementRequest,
) (*model.Announcement, error) {
	if current == nil {
		return nil, ErrAnnouncementNotFound
	}

	next := *current
	next.StartsAt = cloneTimePtr(current.StartsAt)
	next.EndsAt = cloneTimePtr(current.EndsAt)

	if req.Type != nil {
		typ := strings.TrimSpace(*req.Type)
		if typ == "" {
			return nil, ErrInvalidAnnouncementReq
		}
		next.Type = typ
	}
	if req.Title != nil {
		title := strings.TrimSpace(*req.Title)
		if title == "" {
			return nil, ErrInvalidAnnouncementReq
		}
		next.Title = title
	}
	if req.Content != nil {
		content := strings.TrimSpace(*req.Content)
		if content == "" {
			return nil, ErrInvalidAnnouncementReq
		}
		next.Content = content
	}
	if req.IsEnabled != nil {
		next.IsEnabled = *req.IsEnabled
	}
	if req.StartsAt != nil {
		next.StartsAt = cloneTimePtr(req.StartsAt)
	}
	if req.EndsAt != nil {
		next.EndsAt = cloneTimePtr(req.EndsAt)
	}
	if !isAnnouncementWindowValid(next.StartsAt, next.EndsAt) {
		return nil, ErrInvalidAnnouncementReq
	}

	return &next, nil
}

func isAnnouncementWindowValid(startsAt, endsAt *time.Time) bool {
	if startsAt == nil || endsAt == nil {
		return true
	}
	return endsAt.After(*startsAt)
}

func normalizeAnnouncementPagination(page, pageSize int) (int, int) {
	if page <= 0 {
		page = announcementListDefaultPage
	}
	if pageSize <= 0 {
		pageSize = announcementListDefaultSize
	}
	if pageSize > announcementListMaxPageSize {
		pageSize = announcementListMaxPageSize
	}
	return page, pageSize
}

func scanAnnouncement(src rowScanner) (*model.Announcement, error) {
	item := &model.Announcement{}
	if err := src.Scan(
		&item.ID,
		&item.Type,
		&item.Title,
		&item.Content,
		&item.IsEnabled,
		&item.StartsAt,
		&item.EndsAt,
		&item.CreatedBy,
		&item.CreatedAt,
	); err != nil {
		return nil, err
	}
	return item, nil
}

func (s *AnnouncementService) writeAudit(
	ctx context.Context,
	userID *uuid.UUID,
	action, resourceID string,
	oldValue, newValue map[string]interface{},
) {
	if s.auditRepo == nil {
		return
	}

	resourceType := "announcement"
	_ = s.auditRepo.Create(ctx, &model.AuditLog{
		UserID:       userID,
		Action:       action,
		ResourceType: &resourceType,
		ResourceID:   &resourceID,
		OldValue:     oldValue,
		NewValue:     newValue,
		CreatedAt:    time.Now().UTC(),
	})
}

func (s *AnnouncementService) broadcast(action string, item *model.Announcement) {
	if s.sseHub == nil || item == nil {
		return
	}

	s.sseHub.Broadcast(sse.NewEvent(sse.EventAnnouncement, map[string]interface{}{
		"action":       action,
		"id":           item.ID.String(),
		"type":         item.Type,
		"title":        item.Title,
		"content":      item.Content,
		"is_enabled":   item.IsEnabled,
		"starts_at":    formatTimePtr(item.StartsAt),
		"ends_at":      formatTimePtr(item.EndsAt),
		"created_at":   item.CreatedAt.UTC().Format(time.RFC3339Nano),
		"created_by":   item.CreatedBy.String(),
		"published_at": time.Now().UTC().Format(time.RFC3339Nano),
	}))
}
