// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package wire

import "testing"

func TestCommitCommandsStable(t *testing.T) {
	if CommitCommands["CREATE"] != "commit-create" {
		t.Fatalf("unexpected mapping: %q", CommitCommands["CREATE"])
	}
}
