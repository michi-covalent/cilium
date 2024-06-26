// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eventsmap

import (
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/common"
)

// Cell provides eventsmap.Map, which is the hive representation of the cilium
// events perf event ring buffer.
var Cell = cell.Module(
	"events-map",
	"eBPF ring buffer of cilium events",

	cell.Provide(newEventsMap),
)

var (
	MaxEntries int
)

type Map interface{}

func newEventsMap(log logrus.FieldLogger, lifecycle cell.Lifecycle) bpf.MapOut[Map] {
	eventsMap := &eventsMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			cpus := common.GetNumPossibleCPUs(log)
			err := eventsMap.init(cpus)
			if err != nil {
				return fmt.Errorf("initializing events map: %w", err)
			}
			return nil
		},
		OnStop: func(context cell.HookContext) error {
			// We don't currently care for cleaning up.
			return nil
		},
	})

	return bpf.NewMapOut(Map(eventsMap))
}
