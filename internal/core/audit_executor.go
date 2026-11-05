package core

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

type auditActorKey struct{}
type auditAuthorityKey struct{}

// The wrapper follows the registered executor into action chains as well as
// normal/approved dispatch. It also checks sensor/approver authority after I/O.
type auditedExecutor struct {
	inner ActionExecutor
	audit *AuditService
}

func (x *auditedExecutor) Validate(rule ResponseRule) error { return x.inner.Validate(rule) }
func (x *auditedExecutor) Execute(ctx context.Context, alert *Alert, rule ResponseRule, logger zerolog.Logger) (target, details string, execErr error) {
	if x.audit == nil {
		return "", "", errors.New("durable audit unavailable")
	}
	actor, _ := ctx.Value(auditActorKey{}).(string)
	if actor == "" {
		actor = "automation"
	}
	event := AuditEvent{Kind: "action_intent", RequestID: uuid.NewString(), Actor: actor, Action: string(rule.Action), ResourceHash: AuditResourceHash(alert.ID)}
	_, err := x.audit.Record(ctx, event, true)
	if err != nil {
		return "", "", errors.New("action blocked by durable audit")
	}
	completed := false
	defer func() {
		event.Kind = "action_result"
		event.Outcome = "interrupted"
		if completed {
			if execErr != nil {
				event.Outcome = "failed"
			} else {
				event.Outcome = "succeeded"
			}
		}
		if _, err := x.audit.Record(context.WithoutCancel(ctx), event, false); err != nil && execErr == nil {
			execErr = errors.New("action outcome audit unavailable; inspect the recorded intent and actual host state")
		}
	}()
	allowed := responseActionAllowed(alert, rule.Action)
	if check, ok := ctx.Value(auditAuthorityKey{}).(func() bool); ok {
		allowed = allowed && check()
	}
	if !allowed || ctx.Err() != nil {
		completed = true
		return "", "", errors.New("action authority is no longer active")
	}
	target, details, execErr = x.inner.Execute(ctx, alert, rule, logger)
	completed = true
	return
}
