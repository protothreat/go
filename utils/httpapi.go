// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	threatpb "github.com/protothreat/go/pb"
	"google.golang.org/protobuf/proto"
)

// PostCommand sends POST /api/<command>. If rawPayload is non-nil, or track is non-empty,
// the body is application/x-protobuf (Payload). Otherwise the body is JSON {"payload":…,"permissions":…}.
func PostCommand(
	ctx context.Context,
	hc *http.Client,
	baseURL string,
	command string,
	payload any,
	extraHeaders map[string]string,
	timeout time.Duration,
	rawPayload []byte,
	track []byte,
	permissions []string,
) (any, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	cmd := strings.ToLower(strings.TrimSpace(command))
	if cmd == "" {
		return nil, fmt.Errorf("missing command")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var body []byte
	contentType := ""
	useProto := rawPayload != nil || len(track) > 0
	if useProto {
		msg := &threatpb.Payload{Command: "", Track: bytes.Clone(track)}
		if rawPayload != nil {
			msg.Types = &threatpb.Payload_Raw{Raw: bytes.Clone(rawPayload)}
		} else {
			b, err := json.Marshal(payload)
			if err != nil {
				return nil, err
			}
			msg.Types = &threatpb.Payload_Json{Json: string(b)}
		}
		var err error
		body, err = proto.Marshal(msg)
		if err != nil {
			return nil, err
		}
		contentType = "application/x-protobuf"
	} else {
		perms := permissions
		if len(perms) == 0 {
			perms = []string{"public"}
		}
		wrap := map[string]any{"payload": payload, "permissions": perms}
		var err error
		body, err = json.Marshal(wrap)
		if err != nil {
			return nil, err
		}
		contentType = "application/json"
	}

	u := strings.TrimRight(baseURL, "/") + "/api/" + cmd
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", contentType)
	req.Header.Set("content-length", fmt.Sprintf("%d", len(body)))
	for k, v := range extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http %s: %s", resp.Status, string(data))
	}
	ct := strings.ToLower(resp.Header.Get("content-type"))
	if strings.Contains(ct, "application/octet-stream") {
		return data, nil
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return string(data), nil
	}
	return out, nil
}
