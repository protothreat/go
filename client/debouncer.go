// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package client

import (
	"context"
	"fmt"
	"maps"

	"github.com/protothreat/go/wire"
)

func (p *ProtoThreat) DebouncerCreate(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_create: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["CREATE"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerSetConfig(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_set_config: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["SET_CONFIG"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerDelete(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_delete: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["DELETE"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerList(ctx context.Context, opts map[string]any) (any, error) {
	if opts == nil {
		opts = map[string]any{}
	}
	return p.Command(ctx, wire.DebouncerCommands["LIST"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerGet(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_get: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["GET"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerPermGrant(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_perm_grant: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["PERM_GRANT"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerPermRevoke(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_perm_revoke: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["PERM_REVOKE"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerPermList(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_perm_list: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["PERM_LIST"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerEnqueue(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_enqueue: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["ENQUEUE"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerListEntries(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_list_entries: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["LIST_ENTRIES"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerEntryGet(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_entry_get: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["ENTRY_GET"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerEntryPut(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_entry_put: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["ENTRY_PUT"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerEntryDelete(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_entry_delete: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["ENTRY_DELETE"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerInputKey(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_input_key: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["INPUT_KEY"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerQueueStats(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_queue_stats: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["QUEUE_STATS"], maps.Clone(opts))
}

func (p *ProtoThreat) DebouncerFlushNow(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.debouncer_flush_now: options object required")
	}
	return p.Command(ctx, wire.DebouncerCommands["FLUSH_NOW"], maps.Clone(opts))
}
