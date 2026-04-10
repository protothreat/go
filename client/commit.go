// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package client

import (
	"context"
	"fmt"
	"maps"

	"github.com/protothreat/go/wire"
)

func (p *ProtoThreat) CommitCreate(ctx context.Context, opts map[string]any) (any, error) {
	if opts == nil {
		opts = map[string]any{}
	}
	return p.Command(ctx, wire.CommitCommands["CREATE"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitList(ctx context.Context, opts map[string]any) (any, error) {
	if opts == nil {
		opts = map[string]any{}
	}
	return p.Command(ctx, wire.CommitCommands["LIST"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitItems(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_items: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["ITEMS"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitInfo(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_info: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["INFO"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitHeaderUpdate(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_header_update: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["HEADER_UPDATE"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitDelete(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_delete: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["DELETE"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitStorageGet(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_storage_get: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["STORAGE_GET"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitStoragePut(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_storage_put: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["STORAGE_PUT"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitStorageDelete(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_storage_delete: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["STORAGE_DELETE"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitStoragePatch(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_storage_patch: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["STORAGE_PATCH"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitSearch(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_search: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["SEARCH"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitMassUpdate(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_mass_update: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["MASS"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitMassDelete(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_mass_delete: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["MASS_DELETE"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitPermGrant(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_perm_grant: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["PERM_GRANT"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitPermRevoke(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_perm_revoke: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["PERM_REVOKE"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitPermList(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_perm_list: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["PERM_LIST"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitApply(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_apply: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["APPLY"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitJobList(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_job_list: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["JOB_LIST"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitJobCurrent(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_job_current: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["JOB_CURRENT"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitJobDelete(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_job_delete: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["JOB_DELETE"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitIndexStatus(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_index_status: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["INDEX_STATUS"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitReindex(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_reindex: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["REINDEX"], maps.Clone(opts))
}

func (p *ProtoThreat) CommitStorageSize(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.commit_storage_size: options object required")
	}
	return p.Command(ctx, wire.CommitCommands["STORAGE_SIZE"], maps.Clone(opts))
}
