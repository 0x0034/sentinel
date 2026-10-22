package app

import (
	"context"
	"sort"
	"time"

	"github.com/0x0034/sentinel/internal/config"
	"github.com/0x0034/sentinel/internal/model"
)

type DetailFetcher interface {
	Detail(context.Context, model.Notice) (*model.VulnerabilityDetails, error)
}

func (a *App) enrich(ctx context.Context, sub config.Subscription, notices []model.Notice) error {
	fetcher, ok := a.Fetcher.(DetailFetcher)
	if !ok || !config.IsVulnerabilitySource(sub.Type) {
		return nil
	}
	ids := make([]string, 0, len(notices))
	for _, n := range notices {
		ids = append(ids, n.ID)
	}
	initialized, states, err := a.Store.NoticeStates(ctx, sub.ID, ids)
	if err != nil {
		return err
	}
	if !initialized {
		return nil
	}
	var pending []int
	for i := range notices {
		v := notices[i].Vulnerability
		if v == nil {
			continue
		}
		state, exists := states[notices[i].ID]
		v.Details, v.DetailAttempt = state.Details, state.DetailAttempt
		if v.Details == nil && (!exists || !state.Baseline) {
			pending = append(pending, i)
		}
	}
	sort.SliceStable(pending, func(i, j int) bool {
		return notices[pending[i]].Vulnerability.DetailAttempt.Before(notices[pending[j]].Vulnerability.DetailAttempt)
	})
	lookupCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for attempt, i := range pending {
		if attempt >= 20 || lookupCtx.Err() != nil {
			break
		}
		n := &notices[i]
		n.Vulnerability.DetailAttempt = time.Now().UTC()
		details, err := fetcher.Detail(lookupCtx, *n)
		if err != nil {
			a.Log.Warn("vulnerability detail unavailable", "subscription", sub.ID, "item", n.ID, "error", err)
			continue
		}
		n.Vulnerability.Details = details
	}
	return ctx.Err()
}
