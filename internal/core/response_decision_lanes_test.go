package core

import (
	"testing"
	"time"
)

func TestObservationNotificationsHaveSeparateResponseBudget(t *testing.T) {
	for _, tc := range []struct {
		name     string
		max      int
		cooldown time.Duration
		second   ActionType
	}{
		{"rate", 1, 0, ActionBlockIP},
		{"cooldown", 10, time.Minute, ActionLog},
	} {
		t.Run(tc.name, func(t *testing.T) {
			re := testResponseEngine(t, enforcementConfig("", false))
			defer re.Stop()
			notifications, hostAction := &mockExecutor{}, &mockExecutor{}
			re.executors[ActionLog], re.executors[ActionBlockIP] = notifications, hostAction
			obs := testAlertWithIP("auth_fortress", "192.0.2.16", SeverityCritical)
			obs.ObservationOnly = true
			eligible := testAlertWithIP("auth_fortress", "192.0.2.16", SeverityCritical)
			p := &ResponsePolicy{Enabled: true, MinSeverity: SeverityInfo, MaxActionsPerMin: tc.max, Cooldown: tc.cooldown, Actions: []ResponseRule{{Action: ActionLog, MinSeverity: SeverityInfo}}}
			re.policies[obs.Module] = p
			re.handleAlert(obs)
			p.Actions = []ResponseRule{{Action: tc.second, MinSeverity: SeverityInfo}}
			re.handleAlert(eligible)
			if tc.second == ActionBlockIP && hostAction.callCount != 1 {
				t.Fatal("observation notification consumed eligible action budget")
			}
			if tc.second == ActionLog && notifications.callCount != 2 {
				t.Fatal("observation set cooldown for eligible notification")
			}
		})
	}
}

func TestEventResponseLaneFollowsActiveAuthority(t *testing.T) {
	r := testSensors(t)
	monitor, _ := enrollTestSensor(t, r, "monitor", false)
	permitted, _ := enrollTestSensor(t, r, "local", true)
	observed := signedTestEvent(t, r, monitor)
	local := signedTestEvent(t, r, permitted)
	if EventMayAffectLocalResponse(observed) || !EventMayAffectLocalResponse(local) {
		t.Fatal("expected different detector lanes for signed monitor and local-response credentials")
	}
	explicit := *local
	explicit.ObservationOnly = true
	if EventMayAffectLocalResponse(&explicit) {
		t.Fatal("explicit observation-only must win over credential entitlement")
	}
	if err := r.Revoke(permitted.ID); err != nil {
		t.Fatal(err)
	}
	if EventMayAffectLocalResponse(local) {
		t.Fatal("a locally-authorized event no longer influences eligible state after revocation")
	}
}
