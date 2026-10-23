package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/0x0034/sentinel/internal/model"
)

type NoticeState struct {
	Baseline      bool
	Details       *model.VulnerabilityDetails
	DetailAttempt time.Time
}

func (s *Store) NoticeStates(ctx context.Context, sub string, ids []string) (bool, map[string]NoticeState, error) {
	var initialized bool
	if err := s.db.QueryRowContext(ctx, "SELECT initialized FROM subscriptions WHERE id=?", sub).Scan(&initialized); err != nil {
		return false, nil, err
	}
	states := map[string]NoticeState{}
	if len(ids) == 0 {
		return initialized, states, nil
	}
	args := []any{sub}
	for _, id := range ids {
		args = append(args, id)
	}
	query := "SELECT id,baseline,vulnerability FROM notices WHERE subscription=? AND id IN (" + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + ")"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return false, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, metadata string
		var state NoticeState
		if err := rows.Scan(&id, &state.Baseline, &metadata); err != nil {
			return false, nil, err
		}
		if metadata != "" {
			var v model.Vulnerability
			if err := json.Unmarshal([]byte(metadata), &v); err != nil {
				return false, nil, errors.New("invalid stored vulnerability metadata")
			}
			state.Details, state.DetailAttempt = v.Details, v.DetailAttempt
		}
		states[id] = state
	}
	return initialized, states, rows.Err()
}
