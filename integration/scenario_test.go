// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

//go:build integration

package integration_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/protothreat/go/challenge"
	"github.com/protothreat/go/client"
	"github.com/protothreat/go/utils"
	"github.com/protothreat/go/wire"
	threatpb "github.com/protothreat/go/pb"
	"google.golang.org/protobuf/proto"
)

func requireEnv(t *testing.T, k string) string {
	t.Helper()
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		t.Fatalf("missing env %s", k)
	}
	return v
}

func mapFrom(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("expected object, got %T", v)
	}
	return m
}

func assertOK(t *testing.T, label string, v any) map[string]any {
	t.Helper()
	m := mapFrom(t, v)
	if m["ok"] != true {
		t.Fatalf("%s: %v", label, v)
	}
	return m
}

func runScenario(t *testing.T, ctx context.Context, pt *client.ProtoThreat, apiKeyID, namePrefix string) {
	t.Helper()
	slug := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, namePrefix)
	if slug == "" {
		slug = "bind"
	}
	directDomain := slug + "-direct.example"
	debounceDomain := slug + "-debounce.example"
	debounceKey := slug + "-dk"

	var signingKeyID, chainID, commitID, debouncerID string
	var commitIdx int

	defer func() {
		if debouncerID != "" {
			_, _ = pt.Command(ctx, wire.DebouncerCommands["DELETE"], map[string]any{"id": debouncerID})
		}
		if commitID != "" {
			_, _ = pt.CommitDelete(ctx, map[string]any{"id": commitID})
		}
		if chainID != "" {
			_, _ = pt.BlockchainStop(ctx, map[string]any{"id": chainID})
			_, _ = pt.BlockchainDelete(ctx, map[string]any{"id": chainID, "removeData": true})
		}
		if signingKeyID != "" {
			_, _ = pt.CryptoRemove(ctx, map[string]any{"id": signingKeyID})
		}
	}()

	r, err := pt.CryptoGenerate(ctx, map[string]any{"name": namePrefix + "-signing"})
	if err != nil {
		t.Fatal(err)
	}
	g := assertOK(t, "crypto-generate", r)
	keyObj, _ := g["key"].(map[string]any)
	signingKeyID = fmt.Sprint(keyObj["id"])
	if signingKeyID == "" {
		t.Fatal("missing signing key id")
	}

	r, err = pt.BlockchainCreate(ctx, map[string]any{
		"cryptoKeyId": signingKeyID,
		"chainName":   namePrefix + "-chain",
	})
	if err != nil {
		t.Fatal(err)
	}
	bc := assertOK(t, "blockchain-create", r)
	bchain, _ := bc["blockchain"].(map[string]any)
	chainID = fmt.Sprint(bchain["id"])
	if len(chainID) != 64 {
		t.Fatalf("chain id: %q", chainID)
	}

	r, err = pt.BlockchainList(ctx)
	if err != nil {
		t.Fatal(err)
	}
	bl := assertOK(t, "blockchain-list", r)
	chains, _ := bl["chains"].([]any)
	found := false
	for _, c := range chains {
		cm, ok := c.(map[string]any)
		if ok && strings.EqualFold(fmt.Sprint(cm["id"]), chainID) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("chain not in list")
	}

	r, err = pt.CommitCreate(ctx, map[string]any{"title": namePrefix + "-commit"})
	if err != nil {
		t.Fatal(err)
	}
	cc := assertOK(t, "commit-create", r)
	commitID = fmt.Sprint(cc["id"])
	switch x := cc["idx"].(type) {
	case float64:
		commitIdx = int(x)
	case int:
		commitIdx = x
	default:
		t.Fatalf("commit idx type %T", cc["idx"])
	}
	if len(commitID) != 32 {
		t.Fatalf("commit id %q", commitID)
	}

	r, err = pt.CommitList(ctx, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	cl := assertOK(t, "commit-list", r)
	commits, _ := cl["commits"].([]any)
	found = false
	for _, c := range commits {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		st, _ := cm["settings"].(map[string]any)
		if st != nil && strings.EqualFold(fmt.Sprint(st["id"]), commitID) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("commit not in list")
	}

	r, err = pt.DebouncerCreate(ctx, map[string]any{
		"ownerUserId":          apiKeyID,
		"ownerPrincipalType":   "api",
		"z":                    3,
		"ttlSec":               3600,
		"commitIdx":            commitIdx,
		"targets":              []any{"commit"},
	})
	if err != nil {
		t.Fatal(err)
	}
	dc := assertOK(t, "debouncer-create", r)
	debouncerID = fmt.Sprint(dc["id"])
	if debouncerID == "" {
		t.Fatal("debouncer id")
	}

	r, err = pt.DebouncerList(ctx, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	dl := assertOK(t, "debouncer-list", r)
	dlist, _ := dl["debouncers"].([]any)
	found = false
	for _, d := range dlist {
		dm, ok := d.(map[string]any)
		if ok && fmt.Sprint(dm["id"]) == debouncerID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("debouncer not in list")
	}

	r, err = pt.CommitStoragePut(ctx, map[string]any{
		"id":     commitID,
		"domain": directDomain,
		"input": map[string]any{
			"domain":  directDomain,
			"tagsSet": []any{"binding-e2e", "direct"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	assertOK(t, "commit-storage-put", r)

	for i := 0; i < 3; i++ {
		r, err = pt.DebouncerEnqueue(ctx, map[string]any{
			"id":  debouncerID,
			"key": debounceKey,
			"input": map[string]any{
				"domain":  debounceDomain,
				"tagsSet": []any{fmt.Sprintf("round-%d", i)},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertOK(t, "debouncer-enqueue", r)
	}

	time.Sleep(900 * time.Millisecond)

	r, err = pt.CommitStorageGet(ctx, map[string]any{"id": commitID, "domain": debounceDomain})
	if err != nil {
		t.Fatal(err)
	}
	sg := assertOK(t, "commit-storage-get", r)
	inp, _ := sg["input"].(map[string]any)
	md := map[string]string{}
	if meta, ok := inp["metadataSet"].([]any); ok {
		for _, x := range meta {
			mm, ok := x.(map[string]any)
			if ok {
				md[fmt.Sprint(mm["key"])] = fmt.Sprint(mm["value"])
			}
		}
	}
	if md["debouncer-ttl"] != "3600" || md["debouncer-attempts"] != "3" {
		t.Fatalf("debouncer metadata: %+v", md)
	}

	r, err = pt.CommitItems(ctx, map[string]any{"id": commitID, "limit": 50})
	if err != nil {
		t.Fatal(err)
	}
	ci := assertOK(t, "commit-items", r)
	items, _ := ci["items"].([]any)
	hasDeb, hasDir := false, false
	for _, row := range items {
		rm, ok := row.(map[string]any)
		if !ok {
			continue
		}
		ix := fmt.Sprint(rm["index"])
		if ix == debounceDomain {
			hasDeb = true
		}
		if ix == directDomain {
			hasDir = true
		}
	}
	if !hasDeb || !hasDir {
		t.Fatal("missing rows in commit-items")
	}

	r, err = pt.CommitApply(ctx, map[string]any{
		"id":           commitID,
		"blockchainId": chainID,
		"signingKeyId": signingKeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertOK(t, "commit-apply", r)

	deadline := time.Now().Add(120 * time.Second)
	busy := 1
	for busy > 0 && time.Now().Before(deadline) {
		jr, err := pt.CommitJobList(ctx, map[string]any{"idx": commitIdx})
		if err != nil {
			t.Fatal(err)
		}
		jm := assertOK(t, "commit-job-list", jr)
		jobs, _ := jm["jobs"].([]any)
		busy = 0
		for _, j := range jobs {
			jj, ok := j.(map[string]any)
			if !ok {
				continue
			}
			st := fmt.Sprint(jj["status"])
			if st == "pending" || st == "running" {
				busy++
			}
		}
		if busy == 0 {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if busy > 0 {
		t.Fatal("apply job timeout")
	}

	r, err = pt.BlockchainBlocksPage(ctx, map[string]any{"id": chainID, "limit": 5, "maxOutputs": 64})
	if err != nil {
		t.Fatal(err)
	}
	pg := assertOK(t, "blockchain-blocks-page", r)
	blocks, _ := pg["blocks"].([]any)
	sawDeb, sawDir := false, false
	for _, blk := range blocks {
		bm, ok := blk.(map[string]any)
		if !ok {
			continue
		}
		outs, _ := bm["outputs"].([]any)
		for _, oh := range outs {
			raw, err := hex.DecodeString(fmt.Sprint(oh))
			if err != nil {
				continue
			}
			out := &threatpb.Output{}
			if proto.Unmarshal(raw, out) != nil {
				continue
			}
			ix := string(out.GetIndex())
			if ix == debounceDomain {
				sawDeb = true
			}
			if ix == directDomain {
				sawDir = true
			}
		}
	}
	if !sawDeb || !sawDir {
		t.Fatal("on-chain outputs missing")
	}
}

func TestBindingScenarioHTTP(t *testing.T) {
	if os.Getenv("PROTOTHREAT_BINDING_E2E") != "1" {
		t.Skip("set PROTOTHREAT_BINDING_E2E=1")
	}
	uri := requireEnv(t, "PROTOTHREAT_BINDING_HTTP_URI")
	base, err := utils.ParseProtothreatURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if base.Type != "http" {
		t.Fatalf("expected http URI, got %q", base.Type)
	}

	id := requireEnv(t, "PROTOTHREAT_BINDING_API_ID")
	psk := strings.ToLower(strings.TrimSpace(requireEnv(t, "PROTOTHREAT_BINDING_API_PSK")))
	merged, err := challenge.MergeChallengeSecret(map[string]any{"id": id, "psk": psk}, !base.ChallengePlain)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := challenge.BuildChallengeToken(merged, nil)
	if err != nil {
		t.Fatal(err)
	}

	pt, err := client.NewProtoThreat(client.Options{
		URI:     uri,
		Token:   tok,
		Timeout: 120 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pt.Connect(); err != nil {
		t.Fatal(err)
	}
	defer pt.Disconnect()

	ctx := context.Background()
	prefix := "go" + strconv.FormatInt(time.Now().UnixNano(), 10)
	runScenario(t, ctx, pt, id, prefix)
}
