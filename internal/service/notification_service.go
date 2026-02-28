package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"nodepass-hub/internal/repository"
	"nodepass-hub/pkg/telegram"
	tplfs "nodepass-hub/templates"
)

type NotificationTemplate string

const (
	NotificationQuotaExceeded NotificationTemplate = "quota_exceeded"
	NotificationVIPWarning7D  NotificationTemplate = "vip_expiry_warning_7d"
	NotificationVIPWarning1D  NotificationTemplate = "vip_expiry_warning_1d"
	NotificationNodeOffline   NotificationTemplate = "node_offline"
	NotificationRuleSyncFail  NotificationTemplate = "rule_sync_failed"
	NotificationCodeRedeemed  NotificationTemplate = "code_redeemed"
)

var notificationTemplateFiles = map[NotificationTemplate]string{
	NotificationQuotaExceeded: "notifications/quota_exceeded.tmpl",
	NotificationVIPWarning7D:  "notifications/vip_expiry_warning_7d.tmpl",
	NotificationVIPWarning1D:  "notifications/vip_expiry_warning_1d.tmpl",
	NotificationNodeOffline:   "notifications/node_offline.tmpl",
	NotificationRuleSyncFail:  "notifications/rule_sync_failed.tmpl",
	NotificationCodeRedeemed:  "notifications/code_redeemed.tmpl",
}

type NotificationService struct {
	userRepo   repository.UserRepository
	systemSvc  *SystemService
	pool       *pgxpool.Pool
	logger     *zap.Logger
	templateMu sync.RWMutex
	templates  map[NotificationTemplate]*template.Template
	clientMu   sync.Mutex
	client     *telegram.BotClient
	clientKey  string
}

func NewNotificationService(
	userRepo repository.UserRepository,
	systemSvc *SystemService,
	pool *pgxpool.Pool,
	logger *zap.Logger,
) *NotificationService {
	if logger == nil {
		logger = zap.NewNop()
	}

	return &NotificationService{
		userRepo:  userRepo,
		systemSvc: systemSvc,
		pool:      pool,
		logger:    logger,
		templates: make(map[NotificationTemplate]*template.Template),
	}
}

func (s *NotificationService) SendToUser(
	ctx context.Context,
	userID string,
	templateName NotificationTemplate,
	vars map[string]string,
) error {
	if s.userRepo == nil {
		return errors.New("user repository is nil")
	}

	uid, err := uuid.Parse(strings.TrimSpace(userID))
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

	if user.TelegramID == nil || *user.TelegramID == 0 {
		return nil
	}

	payload := cloneStringMap(vars)
	payload["username"] = user.Username
	text, err := s.renderTemplate(templateName, payload)
	if err != nil {
		return err
	}

	s.sendAsyncWithRetry(*user.TelegramID, text, templateName)
	return nil
}

func (s *NotificationService) SendToAdmins(
	ctx context.Context,
	templateName NotificationTemplate,
	vars map[string]string,
) error {
	if s.pool == nil {
		return errors.New("database pool is nil")
	}

	rows, err := s.pool.Query(
		ctx,
		`SELECT telegram_id, username
		   FROM users
		  WHERE role = 'admin'
		    AND telegram_id IS NOT NULL`,
	)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var telegramID *int64
		var username string
		if err := rows.Scan(&telegramID, &username); err != nil {
			return err
		}
		if telegramID == nil || *telegramID == 0 {
			continue
		}

		payload := cloneStringMap(vars)
		payload["username"] = username
		text, err := s.renderTemplate(templateName, payload)
		if err != nil {
			return err
		}
		s.sendAsyncWithRetry(*telegramID, text, templateName)
	}

	return rows.Err()
}

func (s *NotificationService) SendMarkdownToChat(ctx context.Context, chatID int64, md string) error {
	client, err := s.resolveBotClient(ctx)
	if err != nil {
		return err
	}
	return client.SendMarkdown(chatID, md)
}

func (s *NotificationService) sendAsyncWithRetry(chatID int64, text string, templateName NotificationTemplate) {
	go func() {
		retryDelays := []time.Duration{0, 5 * time.Second, 15 * time.Second, 60 * time.Second}
		var sendErr error
		for i, delay := range retryDelays {
			if i > 0 {
				time.Sleep(delay)
			}

			client, err := s.resolveBotClient(context.Background())
			if err != nil {
				sendErr = err
				continue
			}
			sendErr = client.SendMarkdown(chatID, text)
			if sendErr == nil {
				return
			}
		}

		s.logger.Error("send telegram notification failed",
			zap.Int64("chat_id", chatID),
			zap.String("template", string(templateName)),
			zap.Error(sendErr),
		)
	}()
}

func (s *NotificationService) resolveBotClient(ctx context.Context) (*telegram.BotClient, error) {
	if s.systemSvc == nil {
		return nil, errors.New("system service is nil")
	}

	cfg, err := s.systemSvc.GetConfig(ctx)
	if err != nil {
		return nil, err
	}

	token := strings.TrimSpace(cfg.TelegramConfig.BotToken)
	if token == "" {
		return nil, errors.New("telegram bot token is not configured")
	}

	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	if s.client != nil && s.clientKey == token {
		return s.client, nil
	}

	s.client = telegram.NewBotClient(token, nil)
	s.clientKey = token
	return s.client, nil
}

func (s *NotificationService) renderTemplate(
	templateName NotificationTemplate,
	vars map[string]string,
) (string, error) {
	tpl, err := s.loadTemplate(templateName)
	if err != nil {
		return "", err
	}

	buf := bytes.NewBuffer(nil)
	if err := tpl.Execute(buf, vars); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (s *NotificationService) loadTemplate(name NotificationTemplate) (*template.Template, error) {
	s.templateMu.RLock()
	if tpl, ok := s.templates[name]; ok {
		s.templateMu.RUnlock()
		return tpl, nil
	}
	s.templateMu.RUnlock()

	file, ok := notificationTemplateFiles[name]
	if !ok {
		return nil, fmt.Errorf("notification template not found: %s", name)
	}

	raw, err := tplfs.NotificationTemplateFS.ReadFile(file)
	if err != nil {
		return nil, err
	}

	tpl, err := template.New(file).Parse(string(raw))
	if err != nil {
		return nil, err
	}

	s.templateMu.Lock()
	s.templates[name] = tpl
	s.templateMu.Unlock()
	return tpl, nil
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return make(map[string]string)
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
