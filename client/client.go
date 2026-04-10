// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

// Package client implements the HTTP ProtoThreat client.
package client

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/protothreat/go/challenge"
	"github.com/protothreat/go/utils"
)

const defaultChallengeRefreshMinInterval = 45 * time.Second

func wireAuthHeaders(token string, user map[string]string) map[string]string {
	if len(user) > 0 {
		email := strings.TrimSpace(user["email"])
		password := user["password"]
		if email != "" && password != "" {
			enc := base64.StdEncoding.EncodeToString([]byte(email + ":" + password))
			return map[string]string{"authorization": "User " + enc}
		}
	}
	if strings.TrimSpace(token) != "" {
		return map[string]string{"authorization": "API " + strings.TrimSpace(token)}
	}
	return map[string]string{}
}

// Options configures ProtoThreat.
type Options struct {
	URI                            string
	URL                            string
	Token                          string
	User                           map[string]string // keys: email, password
	APIChallengeSecret             map[string]any
	APIChallengeAutoRefresh        *bool // nil = true when secret set
	APIChallengeRefreshMinInterval time.Duration
	Timeout                        time.Duration
	// TLSSkipVerify disables TLS certificate verification (rejectUnauthorized: false).
	TLSSkipVerify bool
}

// ProtoThreat is an HTTP(S) client with challenge and token auth.
type ProtoThreat struct {
	uri            string
	user           map[string]string
	token          string
	apiSecret      map[string]any
	apiAutoRefresh bool
	apiMinRefresh  time.Duration
	timeout        time.Duration
	tlsSkipVerify  bool

	httpClient *http.Client
	baseURL    string

	apiLastMintMs float64
}

// NewProtoThreat validates options and builds the initial token (challenge) when needed.
func NewProtoThreat(opt Options) (*ProtoThreat, error) {
	rawURI := strings.TrimSpace(opt.URI)
	if rawURI == "" {
		rawURI = strings.TrimSpace(opt.URL)
	}
	if rawURI == "" {
		return nil, fmt.Errorf("ProtoThreat: options.URI (or URL) is required")
	}

	var user map[string]string
	if opt.User != nil {
		email := strings.TrimSpace(opt.User["email"])
		password := opt.User["password"]
		if email == "" || password == "" {
			return nil, fmt.Errorf("ProtoThreat: user.email and user.password are required when using user auth")
		}
		if strings.TrimSpace(opt.Token) != "" {
			return nil, fmt.Errorf("ProtoThreat: use either token or user auth, not both")
		}
		user = map[string]string{"email": email, "password": password}
	}

	var apiSecret map[string]any
	if opt.APIChallengeSecret != nil {
		id := strings.TrimSpace(fmt.Sprint(opt.APIChallengeSecret["id"]))
		if len(id) >= 2 && strings.EqualFold(id[:2], "0x") {
			id = id[2:]
		}
		psk := strings.ToLower(strings.TrimSpace(fmt.Sprint(opt.APIChallengeSecret["psk"])))
		if id != "" && psk != "" {
			apiSecret = map[string]any{"id": id, "psk": psk}
		}
	}

	apiAuto := apiSecret != nil
	if opt.APIChallengeAutoRefresh != nil {
		apiAuto = *opt.APIChallengeAutoRefresh && apiSecret != nil
	}
	minRefresh := defaultChallengeRefreshMinInterval
	if opt.APIChallengeRefreshMinInterval > 0 {
		minRefresh = opt.APIChallengeRefreshMinInterval
	}
	timeout := opt.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	token := strings.TrimSpace(opt.Token)
	if user == nil && token == "" && apiSecret != nil {
		base, err := utils.ParseProtothreatURI(rawURI)
		if err != nil {
			return nil, err
		}
		useHMAC := !base.ChallengePlain
		merged, err := challenge.MergeChallengeSecret(apiSecret, useHMAC)
		if err != nil {
			return nil, err
		}
		var err2 error
		token, err2 = challenge.BuildChallengeToken(merged, nil)
		if err2 != nil {
			return nil, err2
		}
	}

	if token != "" && user == nil {
		if err := challenge.AssertWireAPIToken(token); err != nil {
			return nil, err
		}
	}

	p := &ProtoThreat{
		uri:            rawURI,
		user:           user,
		token:          token,
		apiSecret:      apiSecret,
		apiAutoRefresh: apiAuto && user == nil,
		apiMinRefresh:  minRefresh,
		timeout:        timeout,
		tlsSkipVerify:  opt.TLSSkipVerify,
	}
	if token != "" && apiSecret != nil && user == nil {
		p.apiLastMintMs = challenge.SyncChallengeMintMs(token)
	}
	return p, nil
}

// URI returns the connection URI.
func (p *ProtoThreat) URI() string { return p.uri }

// ChallengeUseHMAC reports whether the parsed URI implies HMAC challenge mode.
func (p *ProtoThreat) ChallengeUseHMAC() bool {
	base, err := utils.ParseProtothreatURI(p.uri)
	if err != nil {
		return true
	}
	return !base.ChallengePlain
}

// Token returns the current API or challenge token.
func (p *ProtoThreat) Token() string { return p.token }

// SetToken updates the token after validation.
func (p *ProtoThreat) SetToken(t string) error {
	nxt := strings.TrimSpace(t)
	if nxt != "" {
		if err := challenge.AssertWireAPIToken(nxt); err != nil {
			return err
		}
	}
	p.token = nxt
	if nxt != "" && p.apiSecret != nil && p.user == nil {
		p.apiLastMintMs = challenge.SyncChallengeMintMs(nxt)
	} else {
		p.apiLastMintMs = 0
	}
	return nil
}

// Connected reports whether Connect was called successfully.
func (p *ProtoThreat) Connected() bool { return p.httpClient != nil }

// HTTPClient returns the underlying client after Connect.
func (p *ProtoThreat) HTTPClient() *http.Client { return p.httpClient }

// RefreshChallengeToken rebuilds the challenge token from APIChallengeSecret.
func (p *ProtoThreat) RefreshChallengeToken() error {
	if p.apiSecret == nil || p.user != nil {
		return nil
	}
	merged, err := challenge.MergeChallengeSecret(p.apiSecret, p.ChallengeUseHMAC())
	if err != nil {
		return err
	}
	tok, err := challenge.BuildChallengeToken(merged, nil)
	if err != nil {
		return err
	}
	return p.SetToken(tok)
}

func (p *ProtoThreat) applyAPIChallengeAutoRefresh() {
	if !p.apiAutoRefresh || p.apiSecret == nil || p.user != nil {
		return
	}
	minMs := float64(p.apiMinRefresh.Milliseconds())
	now := float64(time.Now().UnixMilli())
	if minMs > 0 && p.apiLastMintMs > 0 && now-p.apiLastMintMs < minMs {
		return
	}
	_ = p.RefreshChallengeToken()
}

// Connect opens the HTTP client for http(s) URIs only.
func (p *ProtoThreat) Connect() error {
	if p.httpClient != nil {
		return fmt.Errorf("ProtoThreat: already connected")
	}
	base, err := utils.ParseProtothreatURI(p.uri)
	if err != nil {
		return err
	}
	if base.Type != "http" {
		return fmt.Errorf("ProtoThreat: only http(s) URIs are supported in this binding (got type %q)", base.Type)
	}
	verify := !p.tlsSkipVerify && base.TLS.RejectUnauthorized
	if p.tlsSkipVerify {
		verify = false
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if !verify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in via TLSSkipVerify
	}
	scheme := "http"
	if base.TLS.Enabled {
		scheme = "https"
	}
	p.baseURL = fmt.Sprintf("%s://%s:%d", scheme, base.Host, base.Port)
	p.httpClient = &http.Client{Transport: tr, Timeout: p.timeout + time.Second}
	return nil
}

// Disconnect closes the HTTP client.
func (p *ProtoThreat) Disconnect() {
	p.httpClient = nil
	p.baseURL = ""
}

// Request sends a wire packet: command, payload, optional track and permissions.
// Do not set auth inside the packet; use Options.Token or User.
func (p *ProtoThreat) Request(ctx context.Context, packet map[string]any) (any, error) {
	if _, has := packet["auth"]; has {
		return nil, fmt.Errorf("ProtoThreat: use options.Token only; do not set packet.auth")
	}
	p.applyAPIChallengeAutoRefresh()
	if p.httpClient == nil || p.baseURL == "" {
		return nil, fmt.Errorf("ProtoThreat: not connected")
	}
	cmd := strings.TrimSpace(fmt.Sprint(packet["command"]))
	payload := packet["payload"]
	var track []byte
	if t, ok := packet["track"].([]byte); ok {
		track = t
	}
	var perms []string
	if pl, ok := packet["permissions"].([]any); ok {
		for _, x := range pl {
			perms = append(perms, fmt.Sprint(x))
		}
	}
	var raw []byte
	if b, ok := payload.([]byte); ok {
		raw = b
	}
	headers := wireAuthHeaders(p.token, p.user)
	return utils.PostCommand(ctx, p.httpClient, p.baseURL, cmd, payload, headers, p.timeout, raw, track, perms)
}

// Command calls request with a command name and JSON payload.
func (p *ProtoThreat) Command(ctx context.Context, name string, payload any) (any, error) {
	return p.Request(ctx, map[string]any{"command": name, "payload": payload})
}

// CreateProtoThreat is an alias for NewProtoThreat.
func CreateProtoThreat(opt Options) (*ProtoThreat, error) {
	return NewProtoThreat(opt)
}
