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

func TestParsePtSchemeIsHTTPType(t *testing.T) {
	u, err := ParseProtothreatURI("pt://127.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	if u.Type != "http" || u.Host != "127.0.0.1" || u.Port != 9000 || u.TLS.Enabled {
		t.Fatalf("unexpected: %+v", u)
	}
	u2, err := ParseProtothreatURI("pts://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u2.Type != "http" || u2.Host != "example.com" || u2.Port != 9000 || !u2.TLS.Enabled {
		t.Fatalf("unexpected: %+v", u2)
	}
}
