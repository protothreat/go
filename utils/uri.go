// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package utils

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// TlsConfig describes TLS expectations for a parsed URI.
type TlsConfig struct {
	Enabled            bool
	RejectUnauthorized bool
}

// ParsedUri holds normalized connection fields.
type ParsedUri struct {
	Type           string // "http" (incl. pt:// / pts://), "ws", "unix"
	Host           string
	Port           int
	Path           string
	ChallengePlain bool
	TLS            TlsConfig
}

// ParseProtothreatURI parses http(s), pt(s), unix, ws(s) URIs.
func ParseProtothreatURI(rawURI string) (*ParsedUri, error) {
	raw := strings.TrimSpace(rawURI)
	if raw == "" {
		return nil, fmt.Errorf("ProtoThreat: URI is required")
	}
	lower := strings.ToLower(raw)

	if strings.HasPrefix(lower, "ws://") || strings.HasPrefix(lower, "wss://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		isWSS := strings.EqualFold(u.Scheme, "wss")
		port := 80
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		} else if isWSS {
			port = 443
		}
		pathname := u.Path
		if pathname == "" || pathname == "/" {
			pathname = "/ws"
		}
		return &ParsedUri{
			Type:           "ws",
			Host:           u.Hostname(),
			Port:           port,
			Path:           pathname,
			ChallengePlain: false,
			TLS:            TlsConfig{Enabled: isWSS, RejectUnauthorized: true},
		}, nil
	}

	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, err
		}
		isHTTPS := strings.EqualFold(u.Scheme, "https")
		port := 80
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		} else if isHTTPS {
			port = 443
		}
		q := u.Query()
		challengePlain := q.Get("challenge") == "plain"
		return &ParsedUri{
			Type:           "http",
			Host:           u.Hostname(),
			Port:           port,
			Path:           "",
			ChallengePlain: challengePlain,
			TLS:            TlsConfig{Enabled: isHTTPS, RejectUnauthorized: true},
		}, nil
	}

	if strings.HasPrefix(lower, "pt://") || strings.HasPrefix(lower, "pts://") {
		isTLS := strings.HasPrefix(lower, "pts://")
		normalized := raw
		if isTLS {
			normalized = "https://" + raw[len("pts://"):]
		} else {
			normalized = "http://" + raw[len("pt://"):]
		}
		u, err := url.Parse(normalized)
		if err != nil {
			return nil, err
		}
		port := 9000
		if p := u.Port(); p != "" {
			port, _ = strconv.Atoi(p)
		}
		return &ParsedUri{
			Type:           "http",
			Host:           u.Hostname(),
			Port:           port,
			Path:           "",
			ChallengePlain: false,
			TLS:            TlsConfig{Enabled: isTLS, RejectUnauthorized: true},
		}, nil
	}

	if strings.HasPrefix(lower, "unix://") {
		rest := raw[len("unix://"):]
		if i := strings.IndexAny(rest, "?#"); i >= 0 {
			rest = rest[:i]
		}
		rest = filepath.ToSlash(rest)
		absPath, err := filepath.Abs(rest)
		if err != nil {
			absPath = rest
		}
		return &ParsedUri{
			Type:           "unix",
			Host:           "",
			Port:           0,
			Path:           absPath,
			ChallengePlain: false,
			TLS:            TlsConfig{Enabled: false},
		}, nil
	}

	return nil, fmt.Errorf("ProtoThreat: unsupported URI scheme in %q (expected http:, https:, pt:, pts:, unix:, ws:, or wss:)", raw)
}
