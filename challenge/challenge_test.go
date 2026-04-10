// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package challenge

import "testing"

func TestBuildChallengeTokenPlain(t *testing.T) {
	tok, err := BuildChallengeToken(map[string]any{"id": "abc", "psk": "deadbeef", "useHmac": false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !IsChallengeTokenShape(tok) {
		t.Fatalf("expected challenge shape, got %q", tok)
	}
}

func TestAssertWireRejectsRawIDPSK(t *testing.T) {
	err := AssertWireAPIToken("abcd:beef")
	if err == nil {
		t.Fatal("expected error for raw id:psk")
	}
}
