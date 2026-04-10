// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

// Package challenge builds and verifies API challenge tokens for wire authentication.
package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
)

var hexColonPattern = regexp.MustCompile(`(?i)^[0-9a-f]+:[0-9a-f]+$`)

func resolveID(raw any) string {
	s := strings.TrimSpace(fmt.Sprint(raw))
	if len(s) >= 2 && strings.EqualFold(s[:2], "0x") {
		return s[2:]
	}
	return s
}

func b64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(s))
}

// ParseClientSecret returns id, pskLower, useHMAC from a map (id, psk, …) or "id:psk" string.
func ParseClientSecret(secret any) (id, psk string, useHMAC bool, ok bool) {
	switch v := secret.(type) {
	case map[string]any:
		id = resolveID(v["id"])
		psk = strings.ToLower(strings.TrimSpace(fmt.Sprint(v["psk"])))
		authLower := strings.ToLower(strings.TrimSpace(fmt.Sprint(v["auth"])))
		useHMAC = true
		if u, ok := v["useHmac"].(bool); ok && !u {
			useHMAC = false
		} else if cp, ok := v["challengePlain"].(bool); ok && cp {
			useHMAC = false
		} else if authLower == "plain" {
			useHMAC = false
		} else if authLower == "hmac" {
			useHMAC = true
		}
		if id != "" && psk != "" {
			return id, psk, useHMAC, true
		}
		return "", "", false, false
	case string:
		raw := strings.TrimSpace(v)
		if raw == "" {
			return "", "", false, false
		}
		if i := strings.IndexByte(raw, ':'); i >= 0 {
			id = resolveID(raw[:i])
			psk = strings.ToLower(strings.TrimSpace(raw[i+1:]))
			if id != "" && psk != "" {
				return id, psk, false, true
			}
		}
	}
	return "", "", false, false
}

// ServerAlignedTimeMs returns server-aligned time in milliseconds.
func ServerAlignedTimeMs(localNowMs, serverTimeMsAtSync, localTimeMsAtSync float64) float64 {
	return serverTimeMsAtSync + (localNowMs - localTimeMsAtSync)
}

// BuildChallengeToken builds a wire challenge token from secret (map or id:psk string).
func BuildChallengeToken(secret any, challenge any) (string, error) {
	id, psk, useHMAC, ok := ParseClientSecret(secret)
	if !ok {
		return "", fmt.Errorf("build_challenge_token: invalid secret (expected { id, psk } or id:psk)")
	}
	var challengeValue string
	if challenge == nil || strings.TrimSpace(fmt.Sprint(challenge)) == "" {
		challengeValue = fmt.Sprintf("%d", time.Now().UnixMilli())
	} else {
		challengeValue = strings.TrimSpace(fmt.Sprint(challenge))
	}
	if !useHMAC {
		b, err := json.Marshal(map[string]string{"id": id, "challenge": challengeValue, "secret": psk})
		if err != nil {
			return "", err
		}
		return b64urlEncode(b), nil
	}
	key, err := hex.DecodeString(psk)
	if err != nil {
		return "", fmt.Errorf("build_challenge_token: psk must be hex for HMAC mode: %w", err)
	}
	payload := id + ":" + challengeValue
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	signature := hex.EncodeToString(mac.Sum(nil))
	b, err := json.Marshal(map[string]string{"id": id, "challenge": challengeValue, "signature": signature})
	if err != nil {
		return "", err
	}
	return b64urlEncode(b), nil
}

// MergeChallengeSecret returns a copy of cred with useHmac set.
func MergeChallengeSecret(cred map[string]any, challengeUseHMAC bool) (map[string]any, error) {
	if cred == nil {
		return nil, fmt.Errorf("merge_challenge_secret: expected { id, psk }")
	}
	out := make(map[string]any, len(cred)+1)
	for k, v := range cred {
		out[k] = v
	}
	out["useHmac"] = challengeUseHMAC
	return out, nil
}

// DecodeChallengeTokenPayload decodes the JSON inside a challenge token, or nil on failure.
func DecodeChallengeTokenPayload(token string) any {
	raw, err := b64urlDecode(strings.TrimSpace(token))
	if err != nil {
		return nil
	}
	var data any
	if json.Unmarshal(raw, &data) != nil {
		return nil
	}
	return data
}

// IsChallengeTokenShape reports whether token decodes to a plausible challenge payload.
func IsChallengeTokenShape(token string) bool {
	data, ok := DecodeChallengeTokenPayload(token).(map[string]any)
	if !ok {
		return false
	}
	if strings.TrimSpace(fmt.Sprint(data["challenge"])) == "" {
		return false
	}
	if resolveID(data["id"]) == "" {
		return false
	}
	hasPlain := strings.TrimSpace(fmt.Sprint(data["secret"])) != "" || strings.TrimSpace(fmt.Sprint(data["psk"])) != ""
	hasSig := strings.TrimSpace(fmt.Sprint(data["signature"])) != ""
	return hasPlain || hasSig
}

// AssertWireAPIToken rejects raw id:psk strings and invalid shapes (parity with Python client).
func AssertWireAPIToken(token string) error {
	raw := strings.TrimSpace(token)
	if raw == "" {
		return nil
	}
	if IsChallengeTokenShape(raw) {
		return nil
	}
	if len(raw) < 512 && hexColonPattern.MatchString(raw) {
		return fmt.Errorf("ProtoThreat: raw id:psk is not accepted; use BuildChallengeToken(secret) and pass the returned token")
	}
	return fmt.Errorf("ProtoThreat: token must be a challenge token from BuildChallengeToken(secret); user/password auth is not supported here")
}

// SyncChallengeMintMs extracts mint time from embedded challenge field when it is a numeric string (ms).
func SyncChallengeMintMs(token string) float64 {
	if token == "" {
		return 0
	}
	d, ok := DecodeChallengeTokenPayload(token).(map[string]any)
	if !ok {
		return 0
	}
	ch := strings.TrimSpace(fmt.Sprint(d["challenge"]))
	if ch == "" {
		return 0
	}
	var ts float64
	if _, err := fmt.Sscanf(ch, "%f", &ts); err == nil && ts > 0 {
		return ts
	}
	return float64(time.Now().UnixMilli())
}

// IsFinite is a small helper for maxAgeMs checks.
func IsFinite(f float64) bool {
	return !math.IsInf(f, 0) && !math.IsNaN(f)
}
