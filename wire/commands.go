// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

// Package wire holds stable kernel command name strings.
package wire

// CommitCommands maps logical names to commit-* wire commands.
var CommitCommands = map[string]string{
	"CREATE":         "commit-create",
	"LIST":           "commit-list",
	"ITEMS":          "commit-items",
	"INFO":           "commit-info",
	"HEADER_UPDATE":  "commit-header-update",
	"DELETE":         "commit-delete",
	"STORAGE_GET":    "commit-storage-get",
	"STORAGE_PUT":    "commit-storage-put",
	"STORAGE_DELETE": "commit-storage-delete",
	"STORAGE_PATCH":  "commit-storage-patch",
	"SEARCH":         "commit-search",
	"MASS":           "commit-mass-update",
	"MASS_DELETE":    "commit-mass-delete",
	"PERM_GRANT":     "commit-perm-grant",
	"PERM_REVOKE":    "commit-perm-revoke",
	"PERM_LIST":      "commit-perm-list",
	"APPLY":          "commit-apply",
	"JOB_LIST":       "commit-job-list",
	"JOB_CURRENT":    "commit-job-current",
	"JOB_DELETE":     "commit-job-delete",
	"INDEX_STATUS":   "commit-index-status",
	"REINDEX":        "commit-reindex",
	"STORAGE_SIZE":   "commit-storage-size",
}

// BlockchainCommands maps logical names to blockchain-* wire commands.
var BlockchainCommands = map[string]string{
	"LIST":             "blockchain-list",
	"LIST_PUBLIC":      "blockchain-list-public",
	"LIST_WRITABLE":    "blockchain-list-writable",
	"INFO":             "blockchain-info",
	"STATS":            "blockchain-stats",
	"SIZE":             "blockchain-size",
	"BLOCK_GET":        "blockchain-block-get",
	"BLOCKS_PAGE":      "blockchain-blocks-page",
	"CREATE":           "blockchain-create",
	"UPDATE":           "blockchain-update",
	"START":            "blockchain-start",
	"STOP":             "blockchain-stop",
	"DELETE":           "blockchain-delete",
	"ENQUEUE":          "blockchain-enqueue",
	"EXPLORER_START":   "blockchain-explorer-start",
	"EXPLORER_STOP":    "blockchain-explorer-stop",
	"EXPLORER_LIST":    "blockchain-explorer-list",
	"BOOTSTRAP":        "blockchain-bootstrap",
	"BOOTSTRAP_PUBLIC": "blockchain-bootstrap-public",
	"SEARCH":           "blockchain-search",
	"INDEX_GET":        "blockchain-index-get",
}

// DebouncerCommands maps logical names to debouncer-* wire commands.
var DebouncerCommands = map[string]string{
	"CREATE":       "debouncer-create",
	"SET_CONFIG":   "debouncer-set-config",
	"DELETE":       "debouncer-delete",
	"LIST":         "debouncer-list",
	"GET":          "debouncer-get",
	"PERM_GRANT":   "debouncer-perm-grant",
	"PERM_REVOKE":  "debouncer-perm-revoke",
	"PERM_LIST":    "debouncer-perm-list",
	"ENQUEUE":      "debouncer-enqueue",
	"LIST_ENTRIES": "debouncer-list-entries",
	"ENTRY_GET":    "debouncer-entry-get",
	"ENTRY_PUT":    "debouncer-entry-put",
	"ENTRY_DELETE": "debouncer-entry-delete",
	"INPUT_KEY":    "debouncer-input-key",
	"QUEUE_STATS":  "debouncer-queue-stats",
	"FLUSH_NOW":    "debouncer-flush-now",
}
