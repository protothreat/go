// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package utils

import "testing"

func TestParseHTTP(t *testing.T) {
	u, err := ParseProtothreatURI("http://127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	if u.Type != "http" || u.Host != "127.0.0.1" || u.Port != 8080 {
		t.Fatalf("unexpected: %+v", u)
	}
}

func TestParseHTTPSChallengePlain(t *testing.T) {
	u, err := ParseProtothreatURI("https://example.com?challenge=plain")
	if err != nil {
		t.Fatal(err)
	}
	if !u.ChallengePlain {
		t.Fatal("expected challenge=plain")
	}
}

func TestParsePTSchemeIsHTTP(t *testing.T) {
	u, err := ParseProtothreatURI("pt://127.0.0.1:9001")
	if err != nil {
		t.Fatal(err)
	}
	if u.Type != "http" || u.Host != "127.0.0.1" || u.Port != 9001 || u.TLS.Enabled {
		t.Fatalf("unexpected: %+v", u)
	}
	u2, err := ParseProtothreatURI("pts://127.0.0.1/")
	if err != nil {
		t.Fatal(err)
	}
	if u2.Type != "http" || !u2.TLS.Enabled || u2.Port != 9000 {
		t.Fatalf("unexpected: %+v", u2)
	}
}
