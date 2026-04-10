// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package client

import (
	"context"
	"fmt"
	"maps"

	"github.com/protothreat/go/wire"
)

func (p *ProtoThreat) BlockchainListWritable(ctx context.Context) (any, error) {
	return p.Command(ctx, wire.BlockchainCommands["LIST_WRITABLE"], map[string]any{})
}

func (p *ProtoThreat) BlockchainSize(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_size: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["SIZE"], maps.Clone(opts))
}

func (p *ProtoThreat) BlockchainBlockGet(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_block_get: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["BLOCK_GET"], maps.Clone(opts))
}

func (p *ProtoThreat) BlockchainBlocksPage(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_blocks_page: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["BLOCKS_PAGE"], maps.Clone(opts))
}

func (p *ProtoThreat) BlockchainStart(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_start: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["START"], maps.Clone(opts))
}

func (p *ProtoThreat) BlockchainStop(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_stop: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["STOP"], maps.Clone(opts))
}

func (p *ProtoThreat) BlockchainExplorerStart(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_explorer_start: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["EXPLORER_START"], maps.Clone(opts))
}

func (p *ProtoThreat) BlockchainExplorerStop(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_explorer_stop: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["EXPLORER_STOP"], maps.Clone(opts))
}

func (p *ProtoThreat) BlockchainExplorerList(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_explorer_list: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["EXPLORER_LIST"], maps.Clone(opts))
}

func (p *ProtoThreat) BlockchainBootstrap(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_bootstrap: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["BOOTSTRAP"], maps.Clone(opts))
}

func (p *ProtoThreat) BlockchainBootstrapPublic(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_bootstrap_public: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["BOOTSTRAP_PUBLIC"], maps.Clone(opts))
}

func (p *ProtoThreat) BlockchainSearch(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_search: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["SEARCH"], maps.Clone(opts))
}

func (p *ProtoThreat) BlockchainIndexGet(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_index_get: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["INDEX_GET"], maps.Clone(opts))
}
