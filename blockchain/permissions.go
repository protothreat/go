// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package blockchain

import (
	"fmt"
	"strings"
)

// BlockchainPerms maps short names to wire permission strings.
var BlockchainPerms = map[string]string{
	"READ":               "chain_read",
	"WRITE":              "chain_write",
	"FULL_EXPLORER_VIEW": "chain_full_explorer_view",
	"INDEX_KEY_SEARCH":   "chain_index_key_search",
	"TEXT_SEARCH":        "chain_text_search",
	"MCP_INTERCONNECT":   "chain_mcp_interconnect",
	"REDISTRIBUTE":       "chain_redistribute",
	"MERGE":              "chain_merge",
}

var allBlockchainPerms map[string]struct{}

func init() {
	allBlockchainPerms = make(map[string]struct{}, len(BlockchainPerms))
	for _, v := range BlockchainPerms {
		allBlockchainPerms[v] = struct{}{}
	}
}

// IsValidBlockchainPerm reports whether s is a known chain permission token.
func IsValidBlockchainPerm(perm string) bool {
	_, ok := allBlockchainPerms[perm]
	return ok
}

// NormalizeBlockchainPerms deduplicates and lowercases valid permission strings.
func NormalizeBlockchainPerms(raw any) []string {
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	for _, v := range list {
		s := strings.ToLower(strings.TrimSpace(fmt.Sprint(v)))
		if IsValidBlockchainPerm(s) {
			if _, dup := seen[s]; !dup {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	return out
}

// NormalizeBlockchainPermissionsMap normalizes a chain id -> perms map.
func NormalizeBlockchainPermissionsMap(raw any) map[string][]string {
	m, ok := raw.(map[string]any)
	if !ok || len(m) == 0 {
		return map[string][]string{}
	}
	out := make(map[string][]string)
	for chainID, perms := range m {
		id := strings.ToLower(strings.TrimSpace(chainID))
		if id == "" {
			continue
		}
		lst := NormalizeBlockchainPerms(perms)
		if len(lst) > 0 {
			out[id] = lst
		}
	}
	return out
}

// HasBlockchainPerm checks requiredPerm for chainID in permMap.
func HasBlockchainPerm(permMap map[string][]string, chainID, requiredPerm string) bool {
	if len(permMap) == 0 {
		return false
	}
	id := strings.ToLower(strings.TrimSpace(chainID))
	perms, ok := permMap[id]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == requiredPerm {
			return true
		}
	}
	return false
}
