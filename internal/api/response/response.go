package response

import "github.com/gin-gonic/gin"

const (
	CodeSuccess = 0
)

const (
	ErrUnauthorized = 10001
	ErrTokenExpired = 10002
	ErrForbidden    = 10003
)

const (
	ErrUserNotFound  = 20001
	ErrUserBanned    = 20002
	ErrPasswordWrong = 20003
)

const (
	ErrNodeNotFound  = 30001
	ErrPortExhausted = 30002
	ErrNodeOffline   = 30003
)

const (
	ErrRuleNotFound      = 40001
	ErrRuleLimitExceeded = 40002
)

const (
	ErrQuotaExceeded = 50001
)

const (
	ErrCodeNotFound = 60001
	ErrCodeUsed     = 60002
	ErrCodeExpired  = 60003
)

const (
	ErrSystemMaintenance = 90001
	ErrInternal          = 99999
)

type Response struct {
	Code       int         `json:"code"`
	Message    string      `json:"message"`
	Data       any         `json:"data,omitempty"`
	Pagination *Pagination `json:"pagination,omitempty"`
}

type Pagination struct {
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
	Total    int64 `json:"total"`
}

func Success(c *gin.Context, data any) {
	c.JSON(200, Response{
		Code:    CodeSuccess,
		Message: "success",
		Data:    data,
	})
}

func Paginated(c *gin.Context, data any, page, pageSize int, total int64) {
	c.JSON(200, Response{
		Code:    CodeSuccess,
		Message: "success",
		Data:    data,
		Pagination: &Pagination{
			Page:     page,
			PageSize: pageSize,
			Total:    total,
		},
	})
}

func Fail(c *gin.Context, httpStatus, appCode int, message string) {
	c.JSON(httpStatus, Response{
		Code:    appCode,
		Message: message,
	})
}
