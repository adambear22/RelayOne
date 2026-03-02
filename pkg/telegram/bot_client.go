package telegram

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const telegramAPIBase = "https://api.telegram.org"

type BotClient struct {
	token      string
	httpClient *http.Client
}

type sendMessageRequest struct {
	ChatID                int64  `json:"chat_id"`
	Text                  string `json:"text"`
	ParseMode             string `json:"parse_mode,omitempty"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview,omitempty"`
}

type telegramAPIResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
}

func NewBotClient(token string, httpClient *http.Client) *BotClient {
	client := httpClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	return &BotClient{
		token:      strings.TrimSpace(token),
		httpClient: client,
	}
}

func (c *BotClient) SendMessage(chatID int64, text string) error {
	return c.send(chatID, text, "")
}

func (c *BotClient) SendMarkdown(chatID int64, md string) error {
	return c.send(chatID, md, "Markdown")
}

func (c *BotClient) send(chatID int64, text string, parseMode string) error {
	if c == nil {
		return errors.New("telegram client is nil")
	}
	if strings.TrimSpace(c.token) == "" {
		return errors.New("telegram bot token is empty")
	}
	if chatID == 0 {
		return errors.New("chat id is required")
	}
	if strings.TrimSpace(text) == "" {
		return errors.New("message is empty")
	}

	body, err := json.Marshal(sendMessageRequest{
		ChatID:                chatID,
		Text:                  text,
		ParseMode:             parseMode,
		DisableWebPagePreview: true,
	})
	if err != nil {
		return err
	}

	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", telegramAPIBase, url.PathEscape(c.token))
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return err
	}
	if !strings.EqualFold(endpointURL.Scheme, "https") || !strings.EqualFold(endpointURL.Host, "api.telegram.org") {
		return errors.New("invalid telegram api endpoint")
	}

	req, err := http.NewRequest(http.MethodPost, endpointURL.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	// #nosec G107,G704 -- endpoint host/scheme are validated above.
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	var apiResp telegramAPIResponse
	if decodeErr := json.NewDecoder(resp.Body).Decode(&apiResp); decodeErr != nil {
		return decodeErr
	}

	if resp.StatusCode >= http.StatusBadRequest || !apiResp.OK {
		if apiResp.Description == "" {
			apiResp.Description = "telegram api request failed"
		}
		return fmt.Errorf("telegram api error: %s", apiResp.Description)
	}

	return nil
}

func VerifyWidgetHash(data map[string]string, botToken string) bool {
	if len(data) == 0 || strings.TrimSpace(botToken) == "" {
		return false
	}

	hash := strings.TrimSpace(data["hash"])
	if len(hash) == 0 {
		return false
	}

	keys := make([]string, 0, len(data))
	for key := range data {
		if key == "hash" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+data[key])
	}
	dataCheckString := strings.Join(parts, "\n")

	secret := sha256.Sum256([]byte(strings.TrimSpace(botToken)))
	mac := hmac.New(sha256.New, secret[:])
	_, _ = mac.Write([]byte(dataCheckString))
	expected := hex.EncodeToString(mac.Sum(nil))

	if len(expected) != len(hash) {
		return false
	}
	return hmac.Equal([]byte(strings.ToLower(expected)), []byte(strings.ToLower(hash)))
}

func ParseAuthDate(raw string) (time.Time, error) {
	authTS, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil || authTS <= 0 {
		return time.Time{}, errors.New("invalid auth_date")
	}
	return time.Unix(authTS, 0).UTC(), nil
}
