package postgres

import (
	"encoding/json"

	"github.com/jackc/pgx/v5/pgconn"

	"nodepass-hub/internal/repository"
)

var ErrNotFound = repository.ErrNotFound

func normalizePagination(page repository.Pagination) (int32, int32) {
	limit := page.Limit
	offset := page.Offset

	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	return limit, offset
}

func decodeJSONMap(raw []byte) (map[string]interface{}, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}

	return out, nil
}

func encodeJSONMap(value map[string]interface{}) ([]byte, error) {
	if value == nil {
		return nil, nil
	}

	return json.Marshal(value)
}

func ensureAffected(tag pgconn.CommandTag) error {
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func int16PtrToIntPtr(v *int16) *int {
	if v == nil {
		return nil
	}
	out := int(*v)
	return &out
}

func intPtrToInt16Ptr(v *int) *int16 {
	if v == nil {
		return nil
	}

	const maxInt16 = int(^uint16(0) >> 1)
	const minInt16 = -maxInt16 - 1

	value := *v
	if value > maxInt16 {
		value = maxInt16
	}
	if value < minInt16 {
		value = minInt16
	}

	out := int16(value)
	return &out
}
