// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

// Package protothreat is the Go binding for the ProtoThreat wire protocol and HTTP client.
//
// Subpackages:
//   - client: HTTP ProtoThreat client and command helpers
//   - challenge: API challenge token helpers
//   - wire: stable kernel command name maps
//   - pb: generated protobuf types (threat.proto)
//   - utils: encoding, wire decode, URI and IP index parsing, HTTP posts
//   - commit, blockchain: commit drafts, bootstrap, permissions, storage paths
//
// Module path: github.com/protothreat/go (see https://github.com/protothreat/go).
// Version aligns with tagged protothreat binding releases for this module.
package protothreat

// Version is the binding release number (protothreat product line).
const Version = "2.0.0"
