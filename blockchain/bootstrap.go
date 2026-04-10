// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package blockchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	threatpb "github.com/protothreat/go/pb"
	"github.com/protothreat/go/utils"
	"google.golang.org/protobuf/proto"
)

const (
	blockchainBootstrapFormatVersion = 1
)

// BootstrapURLProtocolRank ranks URL schemes for preference sorting.
var BootstrapURLProtocolRank = map[string]int{
	"pts": 600, "wss": 500, "https": 400, "pt": 300, "ws": 200, "http": 100, "unix": 50,
}

var stripProtothreatPlus = regexp.MustCompile(`(?i)^protothreat\+`)

// StripProtothreatPlusSchemePrefix removes a protothreat+ scheme prefix.
func StripProtothreatPlusSchemePrefix(rawURL string) string {
	return stripProtothreatPlus.ReplaceAllString(rawURL, "")
}

// NormalizeHostnameForIPCheck strips brackets around IPv6 hostnames.
func NormalizeHostnameForIPCheck(hostname string) string {
	h := strings.TrimSpace(hostname)
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		return h[1 : len(h)-1]
	}
	return h
}

// BootstrapURLHostPreferenceTier scores hostnames: 0 empty, 1 name, 2 IPv4, 3 IPv6.
func BootstrapURLHostPreferenceTier(hostname string) int {
	h := NormalizeHostnameForIPCheck(hostname)
	if h == "" {
		return 0
	}
	if ip := net.ParseIP(h); ip != nil {
		if ip.To4() != nil {
			return 2
		}
		return 3
	}
	return 1
}

// ParseBootstrapURLForRanking extracts scheme and hostname for sorting.
func ParseBootstrapURLForRanking(rawURL string) map[string]string {
	raw := strings.TrimSpace(rawURL)
	if raw == "" {
		return nil
	}
	peeled := StripProtothreatPlusSchemePrefix(raw)
	lower := strings.ToLower(peeled)
	if strings.HasPrefix(lower, "unix://") {
		return map[string]string{"scheme": "unix", "hostname": "", "raw": raw}
	}
	if strings.HasPrefix(lower, "pt://") || strings.HasPrefix(lower, "pts://") {
		normalized := peeled
		if strings.HasPrefix(lower, "pts://") {
			normalized = "https://" + peeled[len("pts://"):]
		} else {
			normalized = "http://" + peeled[len("pt://"):]
		}
		u, err := url.Parse(normalized)
		if err != nil {
			return nil
		}
		scheme := "pt"
		if strings.HasPrefix(lower, "pts://") {
			scheme = "pts"
		}
		return map[string]string{"scheme": scheme, "hostname": u.Hostname(), "raw": raw}
	}
	u, err := url.Parse(peeled)
	if err != nil {
		return nil
	}
	scheme := strings.ToLower(u.Scheme)
	if _, ok := BootstrapURLProtocolRank[scheme]; ok {
		return map[string]string{"scheme": scheme, "hostname": u.Hostname(), "raw": raw}
	}
	return map[string]string{"scheme": "__other__", "hostname": u.Hostname(), "raw": raw}
}

// BootstrapURLPreferenceScore ranks URLs for mirror selection (higher is better).
func BootstrapURLPreferenceScore(urlStr string) float64 {
	p := ParseBootstrapURLForRanking(urlStr)
	if p == nil {
		return -1e100
	}
	protoRank := BootstrapURLProtocolRank[p["scheme"]]
	host := BootstrapURLHostPreferenceTier(p["hostname"])
	nonHTTPBoost := 0.0
	if p["scheme"] != "http" {
		nonHTTPBoost = 1_000_000
	}
	return nonHTTPBoost + float64(host)*10_000 + float64(protoRank)
}

// SortBootstrapURLsByPreference returns URLs ordered by preference score.
func SortBootstrapURLsByPreference(urls []string) []string {
	type item struct {
		raw   string
		idx   int
		score float64
	}
	var lst []item
	for i, u := range urls {
		s := strings.TrimSpace(u)
		if s == "" {
			continue
		}
		lst = append(lst, item{raw: s, idx: i, score: BootstrapURLPreferenceScore(s)})
	}
	sort.SliceStable(lst, func(i, j int) bool {
		if lst[i].score == lst[j].score {
			return lst[i].idx < lst[j].idx
		}
		return lst[i].score > lst[j].score
	})
	out := make([]string, len(lst))
	for i := range lst {
		out[i] = lst[i].raw
	}
	return out
}

// PickPreferredBootstrapURL returns the highest-ranked URL or empty string.
func PickPreferredBootstrapURL(urls []string) string {
	s := SortBootstrapURLsByPreference(urls)
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

// BlockTimestampToNumber returns block timestamp in ms or current time.
func BlockTimestampToNumber(block *threatpb.Block) int64 {
	if block == nil {
		return time.Now().UnixMilli()
	}
	return block.Timestamp
}

// BlockForCryptoVerify returns a shallow copy with normalized timestamp.
func BlockForCryptoVerify(block *threatpb.Block) *threatpb.Block {
	if block == nil {
		return nil
	}
	b := proto.Clone(block).(*threatpb.Block)
	b.Timestamp = BlockTimestampToNumber(block)
	return b
}

// HashHeaderSum returns SHA-256 of the header wire encoding.
func HashHeaderSum(header *threatpb.Header) []byte {
	if header == nil {
		return nil
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(header)
	if err != nil {
		return nil
	}
	h := sha256.Sum256(b)
	return h[:]
}

func bytesEqual(a, b []byte) bool { return bytes.Equal(a, b) }

func strPtrVal(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

// ValidateBlockchainBootstrapStruct checks genesis fields and chain id consistency.
func ValidateBlockchainBootstrapStruct(msg *threatpb.BlockchainBootstrap) map[string]any {
	errs := []string{}
	if msg == nil {
		return map[string]any{"ok": false, "errors": []string{"bootstrap message missing"}, "hasApiAccessToken": false}
	}
	fv := msg.FormatVersion
	if fv == 0 {
		fv = blockchainBootstrapFormatVersion
	}
	if fv != blockchainBootstrapFormatVersion {
		errs = append(errs, fmt.Sprintf("format_version must be %d", blockchainBootstrapFormatVersion))
	}
	gh := msg.GetGenesisHeader()
	gb := msg.GetGenesisBlock()
	if gh == nil || proto.Size(gh) == 0 {
		errs = append(errs, "genesis_header required")
	}
	if gb == nil || proto.Size(gb) == 0 {
		errs = append(errs, "genesis_block required")
	}
	hasTok := strPtrVal(msg.ApiAccessToken) != ""
	for _, e := range errs {
		if strings.Contains(e, "genesis") {
			return map[string]any{"ok": false, "errors": errs, "hasApiAccessToken": hasTok}
		}
	}

	sum := HashHeaderSum(gh)
	chainIDHex := fmt.Sprintf("%x", sum)

	if exp := strPtrVal(msg.ExpectedChainId); exp != "" {
		want, err := utils.ValidateBlockchainID(exp)
		if err != nil {
			errs = append(errs, err.Error())
		} else if want != chainIDHex {
			errs = append(errs, "expected_chain_id does not match genesis_header hash")
		}
	}
	wantPrev := HashHeaderSum(gh)
	if !bytesEqual(gb.GetPrev(), wantPrev) {
		errs = append(errs, "genesis_block.prev must equal SHA-256(Header.encode(genesis_header))")
	}

	return map[string]any{
		"ok": len(errs) == 0, "errors": errs, "chainIdHex": chainIDHex, "hasApiAccessToken": hasTok,
	}
}

// ValidateBlockchainBootstrapWithKernel validates structure; signature_ok is always nil until a kernel is wired.
func ValidateBlockchainBootstrapWithKernel(msg *threatpb.BlockchainBootstrap, kernel any) map[string]any {
	st := ValidateBlockchainBootstrapStruct(msg)
	if st["ok"] != true {
		out := map[string]any{}
		for k, v := range st {
			out[k] = v
		}
		out["signature_ok"] = nil
		return out
	}
	_ = kernel
	out := map[string]any{}
	for k, v := range st {
		out[k] = v
	}
	out["signature_ok"] = nil
	return out
}

// EncodeBlockchainBootstrap serializes for wire, clearing empty tokens and fixing format version.
func EncodeBlockchainBootstrap(msg *threatpb.BlockchainBootstrap) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("nil message")
	}
	out := proto.Clone(msg).(*threatpb.BlockchainBootstrap)
	if out.FormatVersion == 0 {
		out.FormatVersion = blockchainBootstrapFormatVersion
	}
	if strPtrVal(out.ApiAccessToken) == "" {
		out.ApiAccessToken = nil
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(out)
}

// RedactBlockchainBootstrapForPublic strips API tokens for public handoff.
func RedactBlockchainBootstrapForPublic(msg *threatpb.BlockchainBootstrap) *threatpb.BlockchainBootstrap {
	if msg == nil {
		return nil
	}
	out := proto.Clone(msg).(*threatpb.BlockchainBootstrap)
	out.ApiAccessToken = nil
	if out.FormatVersion == 0 {
		out.FormatVersion = blockchainBootstrapFormatVersion
	}
	return out
}

// DecodeBlockchainBootstrap parses binary protobuf.
func DecodeBlockchainBootstrap(raw []byte) (*threatpb.BlockchainBootstrap, error) {
	var m threatpb.BlockchainBootstrap
	if err := proto.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// DecodeBlockchainBootstrapFromPaste parses base64 or data-URL pasted bootstrap blobs.
func DecodeBlockchainBootstrapFromPaste(text string) (*threatpb.BlockchainBootstrap, error) {
	s := regexp.MustCompile(`\s+`).ReplaceAllString(strings.TrimSpace(text), "")
	if i := strings.Index(s, "base64,"); i >= 0 {
		s = s[i+len("base64,"):]
	}
	s = strings.ReplaceAll(strings.ReplaceAll(s, "-", "+"), "_", "/")
	if pad := (-len(s)) % 4; pad != 0 {
		s += strings.Repeat("=", pad)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return DecodeBlockchainBootstrap(raw)
}

// EncodeBlockchainBootstrapToBase64 returns standard base64 wire bytes.
func EncodeBlockchainBootstrapToBase64(msg *threatpb.BlockchainBootstrap) (string, error) {
	b, err := EncodeBlockchainBootstrap(msg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
