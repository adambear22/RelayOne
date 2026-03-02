package jobs

import (
	"github.com/google/uuid"
)

func uuidListToStrings(ids []uuid.UUID) []string {
	if len(ids) == 0 {
		return nil
	}

	values := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == uuid.Nil {
			continue
		}
		values = append(values, id.String())
	}
	return values
}
