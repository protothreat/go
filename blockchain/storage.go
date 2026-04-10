// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package blockchain

import (
	"path/filepath"

	"github.com/protothreat/go/commit"
	"github.com/protothreat/go/utils"
)

// BlockchainChainDir returns the chain subdirectory.
func BlockchainChainDir(blockchainDataDir string) string {
	return filepath.Join(blockchainDataDir, "chain")
}

// BlockchainRequestDir returns the request subdirectory.
func BlockchainRequestDir(blockchainDataDir string) string {
	return filepath.Join(blockchainDataDir, "request")
}

// BlockchainExplorerDir returns the explorer subdirectory.
func BlockchainExplorerDir(blockchainDataDir string) string {
	return filepath.Join(blockchainDataDir, "explorer")
}

// KernelChainRequestIndexDir returns the kernel request index path for chainID.
func KernelChainRequestIndexDir(kernelDataDir, chainID string) (string, error) {
	id, err := utils.ValidateBlockchainID(chainID)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(kernelDataDir)
	if err != nil {
		abs = kernelDataDir
	}
	return filepath.Join(abs, "request", "chain:"+id), nil
}

// MeasureKernelChainRequestIndexBytes reports disk usage for the chain request index.
func MeasureKernelChainRequestIndexBytes(kernelDataDir, chainID string) (int64, error) {
	p, err := KernelChainRequestIndexDir(kernelDataDir, chainID)
	if err != nil {
		return 0, err
	}
	return commit.DirDiskUsageBytes(p), nil
}

// MeasureBlockchainStorageSizes reports chain, request, and explorer byte totals.
func MeasureBlockchainStorageSizes(blockchainDataDir string) map[string]int64 {
	return map[string]int64{
		"chainBytes":    commit.DirDiskUsageBytes(BlockchainChainDir(blockchainDataDir)),
		"requestBytes":  commit.DirDiskUsageBytes(BlockchainRequestDir(blockchainDataDir)),
		"explorerBytes": commit.DirDiskUsageBytes(BlockchainExplorerDir(blockchainDataDir)),
	}
}

// BlockchainStorageSizeCache is a shared cache instance with default TTL settings.
var BlockchainStorageSizeCache = commit.NewCommitStorageSizeCache(map[string]any{
	"ttlMs": commit.DefaultTTLMs(), "maxEntries": commit.DefaultMaxEntries(),
})
