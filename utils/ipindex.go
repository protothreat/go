// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	threatpb "github.com/protothreat/go/pb"
)

// IPStringToAddressBuffer parses an IP string to its packed bytes.
func IPStringToAddressBuffer(ip string) ([]byte, error) {
	s := strings.TrimSpace(ip)
	a := net.ParseIP(s)
	if a == nil {
		return nil, fmt.Errorf("Invalid IP address")
	}
	if v4 := a.To4(); v4 != nil {
		return v4, nil
	}
	return a.To16(), nil
}

// IPv4StringToInt parses dotted IPv4 to uint32 or returns ok false.
func IPv4StringToInt(s string) (uint32, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return 0, false
	}
	var o [4]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 255 {
			return 0, false
		}
		o[i] = n
	}
	return uint32(o[0])<<24 | uint32(o[1])<<16 | uint32(o[2])<<8 | uint32(o[3]), true
}

// IPv4IntToString formats uint32 as dotted IPv4.
func IPv4IntToString(n uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", (n>>24)&255, (n>>16)&255, (n>>8)&255, n&255)
}

// IPv4ApplyPrefix applies a CIDR prefix length to an IPv4 integer.
func IPv4ApplyPrefix(int32 uint32, prefix int) uint32 {
	if prefix <= 0 {
		return 0
	}
	if prefix >= 32 {
		return int32
	}
	mask := uint32(0xFFFFFFFF) << (32 - prefix)
	return int32 & mask
}

// ClearHostBitsAfterPrefixIPv6 clears bits after prefixLen in a 16-byte address.
func ClearHostBitsAfterPrefixIPv6(buf16 []byte, prefixLen int) []byte {
	b := append([]byte(nil), buf16...)
	for i := prefixLen; i < 128; i++ {
		byteIdx := i / 8
		bitInByte := 7 - (i % 8)
		b[byteIdx] &^= 1 << bitInByte
	}
	return b
}

// IPv6BufferToCanonicalString renders16 bytes as lowercase hex quartets.
func IPv6BufferToCanonicalString(buf []byte) string {
	if len(buf) != 16 {
		return ""
	}
	parts := make([]string, 8)
	for i := 0; i < 8; i++ {
		parts[i] = strconv.FormatUint(uint64(binary.BigEndian.Uint16(buf[i*2:i*2+2])), 16)
	}
	return strings.Join(parts, ":")
}

var bracketStrip = regexp.MustCompile(`^\[|\]$`)

// NormalizeIPIndexForInput canonicalizes IP input to CIDR string.
func NormalizeIPIndexForInput(raw string) (string, error) {
	s := bracketStrip.ReplaceAllString(strings.TrimSpace(raw), "")
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return "", fmt.Errorf("Invalid IP address")
		}
		if v4 := ip.To4(); v4 != nil {
			if !regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`).MatchString(s) {
				return "", fmt.Errorf("Value in ip does not look like an IP; use the domain field instead")
			}
			intv, ok := IPv4StringToInt(s)
			if !ok {
				return "", fmt.Errorf("Invalid IPv4 address")
			}
			canon := IPv4IntToString(intv)
			return canon + "/32", nil
		}
		if !strings.Contains(s, ":") {
			return "", fmt.Errorf("Value in ip does not look like an IP; use the domain field instead")
		}
		buf, err := IPStringToAddressBuffer(s)
		if err != nil {
			return "", err
		}
		masked := ClearHostBitsAfterPrefixIPv6(buf, 64)
		canon := IPv6BufferToCanonicalString(masked)
		return canon + "/64", nil
	}

	slash := strings.LastIndex(s, "/")
	addrPart := strings.TrimSpace(s[:slash])
	prefixStr := strings.TrimSpace(s[slash+1:])
	if !regexp.MustCompile(`^\d+$`).MatchString(prefixStr) {
		return "", fmt.Errorf("Invalid CIDR prefix")
	}
	prefix, err := strconv.Atoi(prefixStr)
	if err != nil || prefix < 0 {
		return "", fmt.Errorf("Invalid CIDR prefix")
	}
	ip := net.ParseIP(addrPart)
	if ip == nil {
		return "", fmt.Errorf("Invalid IP address")
	}
	if v4 := ip.To4(); v4 != nil {
		if prefix > 32 {
			return "", fmt.Errorf("IPv4 CIDR prefix must be 0–32")
		}
		intv, ok := IPv4StringToInt(addrPart)
		if !ok {
			return "", fmt.Errorf("Invalid IPv4 address")
		}
		netInt := IPv4ApplyPrefix(intv, prefix)
		canon := IPv4IntToString(netInt)
		if prefix >= 32 {
			return canon + "/32", nil
		}
		return fmt.Sprintf("%s/%d", canon, prefix), nil
	}
	if prefix > 128 {
		return "", fmt.Errorf("IPv6 CIDR prefix must be 0–128")
	}
	buf, err := IPStringToAddressBuffer(addrPart)
	if err != nil {
		return "", err
	}
	masked := ClearHostBitsAfterPrefixIPv6(buf, prefix)
	canon := IPv6BufferToCanonicalString(masked)
	if prefix >= 128 {
		return canon + "/128", nil
	}
	return fmt.Sprintf("%s/%d", canon, prefix), nil
}

// ParsedIPIndexForStorage is the structured form of an IP index row.
type ParsedIPIndexForStorage struct {
	Address []byte
	Mask    int32
	Type    threatpb.Type
}

// ParseIPIndexForStorage parses a normalized IP index string for protobuf Storage rows.
func ParseIPIndexForStorage(indexUTF8 string) (*ParsedIPIndexForStorage, error) {
	if !strings.Contains(indexUTF8, "/") {
		buf, err := IPStringToAddressBuffer(indexUTF8)
		if err != nil {
			return nil, err
		}
		isV6 := len(buf) == 16
		mask := int32(32)
		typ := threatpb.Type_IPv4
		if isV6 {
			mask = 128
			typ = threatpb.Type_IPv6
		}
		return &ParsedIPIndexForStorage{Address: buf, Mask: mask, Type: typ}, nil
	}
	slash := strings.LastIndex(indexUTF8, "/")
	addrPart := strings.TrimSpace(indexUTF8[:slash])
	prefix, err := strconv.Atoi(strings.TrimSpace(indexUTF8[slash+1:]))
	if err != nil {
		return nil, fmt.Errorf("Invalid IP index")
	}
	ip := net.ParseIP(addrPart)
	if ip == nil {
		return nil, fmt.Errorf("Invalid IP index")
	}
	if v4 := ip.To4(); v4 != nil {
		if prefix < 0 || prefix > 32 {
			return nil, fmt.Errorf("IPv4 CIDR prefix must be 0–32")
		}
		intv, ok := IPv4StringToInt(addrPart)
		if !ok {
			return nil, fmt.Errorf("Invalid IPv4 address")
		}
		netInt := IPv4ApplyPrefix(intv, prefix)
		addrBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(addrBuf, netInt)
		return &ParsedIPIndexForStorage{Address: addrBuf, Mask: int32(prefix), Type: threatpb.Type_IPv4}, nil
	}
	if prefix < 0 || prefix > 128 {
		return nil, fmt.Errorf("IPv6 CIDR prefix must be 0–128")
	}
	buf, err := IPStringToAddressBuffer(addrPart)
	if err != nil {
		return nil, err
	}
	masked := ClearHostBitsAfterPrefixIPv6(buf, prefix)
	return &ParsedIPIndexForStorage{Address: masked, Mask: int32(prefix), Type: threatpb.Type_IPv6}, nil
}
