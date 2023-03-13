// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package monitor

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

const (
	debug               = "debug"
	traceSock           = "trace-sock"
	dropNotify          = "drop-notify"
	traceNotify         = "trace-notify"
	policyVerdictNotify = "policy-verdict-notify"
	debugCapture        = "debug-capture"
	accessLog           = "access-log"
	agent               = "agent"
	lost                = "lost"
)

// monitorFilter is an implementation of OnMonitorEvent interface that filters monitor events.
type monitorFilter struct {
	logger              logrus.FieldLogger
	debug               bool
	traceSock           bool
	dropNotify          bool
	traceNotify         bool
	policyVerdictNotify bool
	debuCapture         bool
	accessLog           bool
	agent               bool
	lost                bool
}

// NewMonitorFilter ...
func NewMonitorFilter(logger logrus.FieldLogger, monitorEventFilters []string) (*monitorFilter, error) {
	monitorFilter := monitorFilter{logger: logger}
	for _, filter := range monitorEventFilters {
		switch filter {
		case debug:
			monitorFilter.debug = true
		case traceSock:
			monitorFilter.traceSock = true
		case dropNotify:
			monitorFilter.dropNotify = true
		case traceNotify:
			monitorFilter.traceNotify = true
		case policyVerdictNotify:
			monitorFilter.policyVerdictNotify = true
		case debugCapture:
			monitorFilter.debuCapture = true
		case accessLog:
			monitorFilter.accessLog = true
		case agent:
			monitorFilter.agent = true
		case lost:
			monitorFilter.lost = true
		default:
			return nil, fmt.Errorf("unknown perf event type: %s", filter)
		}
	}
	logger.WithField("filters", monitorEventFilters).Info("Configured Hubble with monitor event filters")
	return &monitorFilter, nil
}

func (m *monitorFilter) OnMonitorEvent(ctx context.Context, event *observerTypes.MonitorEvent) (bool, error) {
	switch payload := event.Payload.(type) {
	case *observerTypes.PerfEvent:
		if len(payload.Data) == 0 {
			return true, errors.ErrEmptyData
		}
		switch payload.Data[0] {
		case monitorAPI.MessageTypeDebug:
			return !m.debug, nil
		case monitorAPI.MessageTypeTraceSock:
			return !m.traceSock, nil
		case monitorAPI.MessageTypeDrop:
			return !m.dropNotify, nil
		case monitorAPI.MessageTypeTrace:
			return !m.traceNotify, nil
		case monitorAPI.MessageTypePolicyVerdict:
			return !m.policyVerdictNotify, nil
		case monitorAPI.MessageTypeCapture:
			return !m.debuCapture, nil
		default:
			return false, nil
		}
	case *observerTypes.AgentEvent:
		switch payload.Type {
		case monitorAPI.MessageTypeAccessLog:
			return !m.accessLog, nil
		case monitorAPI.MessageTypeAgent:
			return !m.agent, nil
		default:
			return true, errors.ErrUnknownEventType
		}
	case *observerTypes.LostEvent:
		return !m.lost, nil
	case nil:
		return true, errors.ErrEmptyData
	default:
		return true, errors.ErrUnknownEventType
	}
}
