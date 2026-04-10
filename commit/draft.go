// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package commit

import (
	"github.com/protothreat/go/utils"
	"github.com/protothreat/go/wire"
)

// CommitCommands is the same map as wire.CommitCommands.
var CommitCommands = wire.CommitCommands

// ParseCommitRef wraps utils.ParseCommitRef.
func ParseCommitRef(ref any) map[string]any { return utils.ParseCommitRef(ref) }

// IndexToPayload wraps utils.IndexToPayload.
func IndexToPayload(indexUTF8 string) map[string]string { return utils.IndexToPayload(indexUTF8) }

// RowKeyParams wraps utils.RowKeyParams.
func RowKeyParams(row map[string]any) map[string]string { return utils.RowKeyParams(row) }

// IPStringToAddressBuffer wraps utils.IPStringToAddressBuffer.
func IPStringToAddressBuffer(ip string) ([]byte, error) { return utils.IPStringToAddressBuffer(ip) }

// NormalizeIPIndexForInput wraps utils.NormalizeIPIndexForInput.
func NormalizeIPIndexForInput(raw string) (string, error) {
	return utils.NormalizeIPIndexForInput(raw)
}

// ParseIPIndexForStorage wraps utils.ParseIPIndexForStorage.
func ParseIPIndexForStorage(indexUTF8 string) (*utils.ParsedIPIndexForStorage, error) {
	return utils.ParseIPIndexForStorage(indexUTF8)
}

// IPv6BufferToCanonicalString wraps utils.IPv6BufferToCanonicalString.
func IPv6BufferToCanonicalString(buf []byte) string { return utils.IPv6BufferToCanonicalString(buf) }

// ClearHostBitsAfterPrefixIPv6 wraps utils.ClearHostBitsAfterPrefixIPv6.
func ClearHostBitsAfterPrefixIPv6(buf16 []byte, prefixLen int) []byte {
	return utils.ClearHostBitsAfterPrefixIPv6(buf16, prefixLen)
}
