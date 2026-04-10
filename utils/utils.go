// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package utils

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	threatpb "github.com/protothreat/go/pb"
	"google.golang.org/protobuf/proto"
)

// ToHex returns lowercase hex for byte-like data.
func ToHex(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	return fmt.Sprintf("%x", data)
}

// Int64ToJSON returns a JSON-friendly timestamp value.
func Int64ToJSON(ts int64) any {
	return ts
}

// BlockToJSON maps a Block to a plain map for logging or JSON APIs.
func BlockToJSON(block *threatpb.Block) map[string]any {
	if block == nil {
		return nil
	}
	outs := make([]string, len(block.Outputs))
	for i, o := range block.Outputs {
		outs[i] = ToHex(o)
	}
	return map[string]any{
		"prev":      ToHex(block.Prev),
		"timestamp": Int64ToJSON(block.Timestamp),
		"outputs":   outs,
		"sum":       ToHex(block.Sum),
		"sign":      ToHex(block.Sign),
		"attach":    ToHex(block.Attach),
	}
}

// HeaderToJSON maps a Header to a plain map.
func HeaderToJSON(header *threatpb.Header) map[string]any {
	if header == nil {
		return nil
	}
	pks := make([]string, len(header.Pubkeys))
	for i, p := range header.Pubkeys {
		pks[i] = ToHex(p)
	}
	return map[string]any{
		"magic":   ToHex(header.Magic),
		"nonce":   ToHex(header.Nonce),
		"pubkeys": pks,
	}
}

type pbReader struct {
	buf []byte
	pos int
}

func (r *pbReader) varint() (uint64, error) {
	var result uint64
	var shift uint
	for r.pos < len(r.buf) {
		b := r.buf[r.pos]
		r.pos++
		result |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return result, nil
		}
		shift += 7
	}
	return 0, fmt.Errorf("truncated varint")
}

func (r *pbReader) uint32() (uint32, error) {
	v, err := r.varint()
	return uint32(v), err
}

func (r *pbReader) bytes() ([]byte, error) {
	ln, err := r.varint()
	if err != nil {
		return nil, err
	}
	end := r.pos + int(ln)
	if end > len(r.buf) {
		return nil, fmt.Errorf("length out of range")
	}
	out := append([]byte(nil), r.buf[r.pos:end]...)
	r.pos = end
	return out, nil
}

func (r *pbReader) skipType(wire int) error {
	switch wire {
	case 0:
		_, err := r.varint()
		return err
	case 1:
		r.pos += 8
		return nil
	case 2:
		ln, err := r.varint()
		if err != nil {
			return err
		}
		r.pos += int(ln)
		return nil
	case 5:
		r.pos += 4
		return nil
	default:
		return fmt.Errorf("unknown wire type %d", wire)
	}
}

// DecodedBlockWire holds a decoded block plus output accounting.
type DecodedBlockWire struct {
	Block            *threatpb.Block
	OutputCountTotal int
	OutputsTruncated bool
}

// DecodeBlockWithOutputLimit decodes Block protobuf wire bytes; caps materialized outputs.
func DecodeBlockWithOutputLimit(raw []byte, maxOutputs int) (*DecodedBlockWire, error) {
	maxN := maxOutputs
	if maxN < 0 {
		maxN = 0
	}
	reader := &pbReader{buf: raw}
	end := len(raw)
	var outputs [][]byte
	var prev, sum, sign, attach []byte
	var timestamp uint64
	field3Count := 0
	outputsTruncated := false

	for reader.pos < end {
		tag, err := reader.uint32()
		if err != nil {
			return nil, err
		}
		field := tag >> 3
		wire := int(tag & 7)
		switch {
		case field == 1 && wire == 2:
			prev, err = reader.bytes()
			if err != nil {
				return nil, err
			}
		case field == 2 && wire == 0:
			timestamp, err = reader.varint()
			if err != nil {
				return nil, err
			}
		case field == 3 && wire == 2:
			ln, err := reader.varint()
			if err != nil {
				return nil, err
			}
			endPos := reader.pos + int(ln)
			if endPos > len(reader.buf) {
				return nil, fmt.Errorf("Block wire: output length out of range")
			}
			field3Count++
			if len(outputs) < maxN {
				outputs = append(outputs, append([]byte(nil), reader.buf[reader.pos:endPos]...))
			} else {
				outputsTruncated = true
			}
			reader.pos = endPos
		case field == 4 && wire == 2:
			sum, err = reader.bytes()
			if err != nil {
				return nil, err
			}
		case field == 5 && wire == 2:
			sign, err = reader.bytes()
			if err != nil {
				return nil, err
			}
		case field == 6 && wire == 2:
			attach, err = reader.bytes()
			if err != nil {
				return nil, err
			}
		default:
			if err := reader.skipType(wire); err != nil {
				return nil, err
			}
		}
	}

	block := &threatpb.Block{
		Prev:      prev,
		Timestamp: int64(timestamp),
		Sum:       sum,
		Sign:      sign,
		Attach:    attach,
		Outputs:   outputs,
	}
	return &DecodedBlockWire{Block: block, OutputCountTotal: field3Count, OutputsTruncated: outputsTruncated}, nil
}

var dottedQuad = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
var digitsOnly = regexp.MustCompile(`^\d+$`)

// LooksLikeIP returns true for IPv4 dotted quads, CIDR strings, or strings containing ':' (IPv6 heuristic).
func LooksLikeIP(value string) bool {
	s := strings.TrimSpace(value)
	if s == "" {
		return false
	}
	if i := strings.LastIndex(s, "/"); i >= 0 {
		addr := strings.TrimSpace(s[:i])
		prefix := strings.TrimSpace(s[i+1:])
		if !digitsOnly.MatchString(prefix) {
			return false
		}
		if strings.HasPrefix(addr, "[") && strings.HasSuffix(addr, "]") {
			addr = addr[1 : len(addr)-1]
		}
		if net.ParseIP(addr) != nil {
			return true
		}
		return false
	}
	if dottedQuad.MatchString(s) {
		return true
	}
	return strings.Contains(s, ":")
}

// ParseCommitRef returns idx (decimal) or id (hex) keys.
func ParseCommitRef(ref any) map[string]any {
	s := strings.TrimSpace(fmt.Sprint(ref))
	if matched, _ := regexp.MatchString(`^\d+$`, s); matched {
		idx, _ := strconv.Atoi(s)
		return map[string]any{"idx": idx}
	}
	h := regexp.MustCompile(`(?i)^0x`).ReplaceAllString(s, "")
	h = strings.ToLower(h)
	if matched, _ := regexp.MatchString(`^[0-9a-f]{32}$`, h); matched {
		return map[string]any{"id": h}
	}
	return map[string]any{"id": h}
}

// IndexToPayload maps an index string to ip or domain key for wire payloads.
func IndexToPayload(indexUTF8 string) map[string]string {
	ix := strings.TrimSpace(indexUTF8)
	if ix == "" {
		return map[string]string{}
	}
	if LooksLikeIP(ix) {
		return map[string]string{"ip": ix}
	}
	return map[string]string{"domain": ix}
}

// RowKeyParams extracts ip or domain from a row map.
func RowKeyParams(row map[string]any) map[string]string {
	ix, ok := row["index"]
	if !ok || ix == nil {
		return map[string]string{}
	}
	s := fmt.Sprint(ix)
	if LooksLikeIP(s) {
		return map[string]string{"ip": s}
	}
	return map[string]string{"domain": s}
}

// ValidateBlockchainID returns normalized 64-char hex or an error.
func ValidateBlockchainID(id string) (string, error) {
	s := strings.TrimSpace(id)
	s = regexp.MustCompile(`(?i)^0x`).ReplaceAllString(s, "")
	s = strings.ToLower(s)
	if len(s) != 64 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s) {
		return "", fmt.Errorf("Blockchain id must be the 64-character hex header hash")
	}
	return s, nil
}

// NormalizeNodeType maps halt -> light and defaults to full.
func NormalizeNodeType(value any) string {
	t := strings.ToLower(strings.TrimSpace(fmt.Sprint(value)))
	if t == "" {
		t = "full"
	}
	if t == "halt" {
		return "light"
	}
	if t == "light" || t == "full" {
		return t
	}
	return "full"
}

// SanitizeChainName validates chain name length and control characters.
func SanitizeChainName(raw any) (string, error) {
	if raw == nil {
		return "", nil
	}
	s := strings.TrimSpace(fmt.Sprint(raw))
	if s == "" {
		return "", nil
	}
	if len(s) > 256 {
		return "", fmt.Errorf("chainName must be at most 256 characters")
	}
	if regexp.MustCompile(`[\x00-\x1f\x7f]`).MatchString(s) {
		return "", fmt.Errorf("chainName must not contain control characters")
	}
	return s, nil
}

// BlockByteSize returns proto size for optional nil-safe use.
func BlockByteSize(b *threatpb.Block) int {
	if b == nil {
		return 0
	}
	return proto.Size(b)
}

// HeaderByteSize returns proto size for optional nil-safe use.
func HeaderByteSize(h *threatpb.Header) int {
	if h == nil {
		return 0
	}
	return proto.Size(h)
}
