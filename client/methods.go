// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) Hafnova AG

package client

import (
	"context"
	"fmt"
	"maps"
	"strconv"

	"github.com/protothreat/go/challenge"
	"github.com/protothreat/go/wire"
)

func setEq[K comparable](a, b map[K]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func keysString(m map[string]any) map[string]struct{} {
	out := make(map[string]struct{}, len(m))
	for k := range m {
		out[k] = struct{}{}
	}
	return out
}

// Health calls health.
func (p *ProtoThreat) Health(ctx context.Context) (any, error) {
	return p.Command(ctx, "health", map[string]any{})
}

// BlockchainList calls blockchain-list.
func (p *ProtoThreat) BlockchainList(ctx context.Context) (any, error) {
	return p.Command(ctx, wire.BlockchainCommands["LIST"], map[string]any{})
}

// BlockchainListPublic calls blockchain-list-public.
func (p *ProtoThreat) BlockchainListPublic(ctx context.Context) (any, error) {
	return p.Command(ctx, wire.BlockchainCommands["LIST_PUBLIC"], map[string]any{})
}

// BlockchainInfo calls blockchain-info with { id }.
func (p *ProtoThreat) BlockchainInfo(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_info: options object required")
	}
	if !setEq(keysString(opts), map[string]struct{}{"id": {}}) || fmt.Sprint(opts["id"]) == "" {
		return nil, fmt.Errorf("ProtoThreat.blockchain_info: only { id } is allowed")
	}
	return p.Command(ctx, wire.BlockchainCommands["INFO"], map[string]any{"id": opts["id"]})
}

// BlockchainStats calls blockchain-stats with { id }.
func (p *ProtoThreat) BlockchainStats(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_stats: options object required")
	}
	if !setEq(keysString(opts), map[string]struct{}{"id": {}}) || fmt.Sprint(opts["id"]) == "" {
		return nil, fmt.Errorf("ProtoThreat.blockchain_stats: only { id } is allowed")
	}
	return p.Command(ctx, wire.BlockchainCommands["STATS"], map[string]any{"id": opts["id"]})
}

// BlockchainCreate calls blockchain-create.
func (p *ProtoThreat) BlockchainCreate(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_create: options object required")
	}
	allowed := map[string]struct{}{"cryptoKeyId": {}, "chainName": {}, "public": {}, "registryListed": {}}
	for k := range opts {
		if _, ok := allowed[k]; !ok {
			return nil, fmt.Errorf("ProtoThreat.blockchain_create: unknown field: %s", k)
		}
	}
	if fmt.Sprint(opts["cryptoKeyId"]) == "" {
		return nil, fmt.Errorf("ProtoThreat.blockchain_create: cryptoKeyId is required")
	}
	payload := map[string]any{"cryptoKeyId": opts["cryptoKeyId"]}
	if v, ok := opts["chainName"]; ok && fmt.Sprint(v) != "" {
		payload["chainName"] = fmt.Sprint(v)
	}
	if opts["public"] == true {
		payload["public"] = true
	}
	if v, ok := opts["registryListed"]; ok {
		payload["registryListed"] = v == true
	}
	return p.Command(ctx, wire.BlockchainCommands["CREATE"], payload)
}

// BlockchainUpdate calls blockchain-update.
func (p *ProtoThreat) BlockchainUpdate(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_update: options object required")
	}
	allowed := map[string]struct{}{"id": {}, "chainName": {}, "public": {}, "registryListed": {}}
	for k := range opts {
		if _, ok := allowed[k]; !ok {
			return nil, fmt.Errorf("ProtoThreat.blockchain_update: unknown field: %s", k)
		}
	}
	if fmt.Sprint(opts["id"]) == "" {
		return nil, fmt.Errorf("ProtoThreat.blockchain_update: id is required")
	}
	payload := map[string]any{"id": opts["id"]}
	if v, ok := opts["chainName"]; ok {
		if v == nil {
			payload["chainName"] = ""
		} else {
			payload["chainName"] = fmt.Sprint(v)
		}
	}
	if v, ok := opts["public"]; ok {
		payload["public"] = v == true
	}
	if v, ok := opts["registryListed"]; ok {
		payload["registryListed"] = v == true
	}
	return p.Command(ctx, wire.BlockchainCommands["UPDATE"], payload)
}

// BlockchainDelete calls blockchain-delete.
func (p *ProtoThreat) BlockchainDelete(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_delete: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["DELETE"], maps.Clone(opts))
}

// BlockchainEnqueue calls blockchain-enqueue.
func (p *ProtoThreat) BlockchainEnqueue(ctx context.Context, opts map[string]any) (any, error) {
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.blockchain_enqueue: options object required")
	}
	return p.Command(ctx, wire.BlockchainCommands["ENQUEUE"], maps.Clone(opts))
}

// CryptoList calls crypto-list.
func (p *ProtoThreat) CryptoList(ctx context.Context, opts map[string]any) (any, error) {
	if opts == nil {
		opts = map[string]any{}
	}
	ks := keysString(opts)
	if len(ks) > 1 || (len(ks) == 1 && !setEq(ks, map[string]struct{}{"scope": {}})) {
		return nil, fmt.Errorf("ProtoThreat.crypto_list: only { scope } is allowed")
	}
	payload := maps.Clone(opts)
	if len(payload) == 0 {
		payload = map[string]any{}
	}
	return p.Command(ctx, "crypto-list", payload)
}

// CryptoShow calls crypto-show.
func (p *ProtoThreat) CryptoShow(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"id": {}}) {
		return nil, fmt.Errorf("ProtoThreat.crypto_show: only { id } is allowed")
	}
	return p.Command(ctx, "crypto-show", map[string]any{"id": opts["id"]})
}

// CryptoGenerate calls crypto-generate.
func (p *ProtoThreat) CryptoGenerate(ctx context.Context, opts map[string]any) (any, error) {
	if opts == nil {
		opts = map[string]any{}
	}
	ks := keysString(opts)
	if len(ks) > 1 || (len(ks) == 1 && !setEq(ks, map[string]struct{}{"name": {}})) {
		return nil, fmt.Errorf("ProtoThreat.crypto_generate: only { name } is allowed")
	}
	payload := map[string]any{}
	if v, ok := opts["name"]; ok && fmt.Sprint(v) != "" {
		payload["name"] = fmt.Sprint(v)
	}
	return p.Command(ctx, "crypto-generate", payload)
}

// CryptoName calls crypto-name.
func (p *ProtoThreat) CryptoName(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"id": {}, "name": {}}) {
		return nil, fmt.Errorf("ProtoThreat.crypto_name: only { id, name } is allowed")
	}
	return p.Command(ctx, "crypto-name", map[string]any{"id": opts["id"], "name": opts["name"]})
}

// CryptoImportPrivate calls crypto-import-private.
func (p *ProtoThreat) CryptoImportPrivate(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"name": {}, "privateBase64": {}}) {
		return nil, fmt.Errorf("ProtoThreat.crypto_import_private: only { name, privateBase64 } is allowed")
	}
	return p.Command(ctx, "crypto-import-private", map[string]any{"name": opts["name"], "privateBase64": opts["privateBase64"]})
}

// CryptoImportPublic calls crypto-import-public.
func (p *ProtoThreat) CryptoImportPublic(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"name": {}, "publicBase64": {}}) {
		return nil, fmt.Errorf("ProtoThreat.crypto_import_public: only { name, publicBase64 } is allowed")
	}
	return p.Command(ctx, "crypto-import-public", map[string]any{"name": opts["name"], "publicBase64": opts["publicBase64"]})
}

// CryptoRemove calls crypto-remove.
func (p *ProtoThreat) CryptoRemove(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"id": {}}) {
		return nil, fmt.Errorf("ProtoThreat.crypto_remove: only { id } is allowed")
	}
	return p.Command(ctx, "crypto-remove", map[string]any{"id": opts["id"]})
}

// APIKeysList calls api-keys-list.
func (p *ProtoThreat) APIKeysList(ctx context.Context) (any, error) {
	return p.Command(ctx, "api-keys-list", map[string]any{})
}

// APIKeyShow calls api-key-show.
func (p *ProtoThreat) APIKeyShow(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"id": {}}) {
		return nil, fmt.Errorf("ProtoThreat.api_key_show: only { id } is allowed")
	}
	return p.Command(ctx, "api-key-show", map[string]any{"id": opts["id"]})
}

// APIKeyGenerate calls api-key-generate.
func (p *ProtoThreat) APIKeyGenerate(ctx context.Context, opts map[string]any) (any, error) {
	for k := range opts {
		if k != "name" && k != "isAdmin" {
			return nil, fmt.Errorf("ProtoThreat.api_key_generate: only { name, isAdmin? } is allowed")
		}
	}
	if fmt.Sprint(opts["name"]) == "" {
		return nil, fmt.Errorf("ProtoThreat.api_key_generate: name is required")
	}
	payload := map[string]any{"name": fmt.Sprint(opts["name"])}
	if v, ok := opts["isAdmin"]; ok {
		if b, ok := v.(bool); ok {
			payload["isAdmin"] = b
		}
	}
	return p.Command(ctx, "api-key-generate", payload)
}

// APIKeyName calls api-key-name.
func (p *ProtoThreat) APIKeyName(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"id": {}, "name": {}}) {
		return nil, fmt.Errorf("ProtoThreat.api_key_name: only { id, name } is allowed")
	}
	return p.Command(ctx, "api-key-name", map[string]any{"id": opts["id"], "name": opts["name"]})
}

// APIKeySetAdmin calls api-key-set-admin.
func (p *ProtoThreat) APIKeySetAdmin(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"id": {}, "isAdmin": {}}) {
		return nil, fmt.Errorf("ProtoThreat.api_key_set_admin: only { id, isAdmin } is allowed")
	}
	b, ok := opts["isAdmin"].(bool)
	if !ok {
		return nil, fmt.Errorf("ProtoThreat.api_key_set_admin: isAdmin must be boolean")
	}
	return p.Command(ctx, "api-key-set-admin", map[string]any{"id": opts["id"], "isAdmin": b})
}

// APIKeyRemove calls api-key-remove.
func (p *ProtoThreat) APIKeyRemove(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"id": {}}) {
		return nil, fmt.Errorf("ProtoThreat.api_key_remove: only { id } is allowed")
	}
	return p.Command(ctx, "api-key-remove", map[string]any{"id": opts["id"]})
}

// APIChallengeBuild calls api-challenge-build.
func (p *ProtoThreat) APIChallengeBuild(ctx context.Context, opts map[string]any) (any, error) {
	for k := range opts {
		if k != "id" && k != "challenge" {
			return nil, fmt.Errorf("ProtoThreat.api_challenge_build: only { id, challenge? } is allowed")
		}
	}
	if fmt.Sprint(opts["id"]) == "" {
		return nil, fmt.Errorf("ProtoThreat.api_challenge_build: id is required")
	}
	payload := map[string]any{"id": fmt.Sprint(opts["id"])}
	if v, ok := opts["challenge"]; ok && fmt.Sprint(v) != "" {
		payload["challenge"] = fmt.Sprint(v)
	}
	return p.Command(ctx, "api-challenge-build", payload)
}

// APIChallengeVerify calls api-challenge-verify.
func (p *ProtoThreat) APIChallengeVerify(ctx context.Context, opts map[string]any) (any, error) {
	for k := range opts {
		if k != "token" && k != "maxAgeMs" {
			return nil, fmt.Errorf("ProtoThreat.api_challenge_verify: only { token, maxAgeMs? } is allowed")
		}
	}
	if fmt.Sprint(opts["token"]) == "" {
		return nil, fmt.Errorf("ProtoThreat.api_challenge_verify: token is required")
	}
	payload := map[string]any{"token": fmt.Sprint(opts["token"])}
	if v, ok := opts["maxAgeMs"]; ok {
		if f, ok := toFloat(v); ok && challenge.IsFinite(f) {
			payload["maxAgeMs"] = f
		}
	}
	return p.Command(ctx, "api-challenge-verify", payload)
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// UserList calls user-list.
func (p *ProtoThreat) UserList(ctx context.Context) (any, error) {
	return p.Command(ctx, "user-list", map[string]any{})
}

// UserShow calls user-show.
func (p *ProtoThreat) UserShow(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"idOrEmail": {}}) {
		return nil, fmt.Errorf("ProtoThreat.user_show: only { idOrEmail } is allowed")
	}
	return p.Command(ctx, "user-show", map[string]any{"idOrEmail": opts["idOrEmail"]})
}

// UserCreate calls user-create.
func (p *ProtoThreat) UserCreate(ctx context.Context, opts map[string]any) (any, error) {
	allowed := map[string]struct{}{"email": {}, "firstName": {}, "lastName": {}, "password": {}, "role": {}}
	for k := range opts {
		if _, ok := allowed[k]; !ok {
			return nil, fmt.Errorf("ProtoThreat.user_create: only { firstName, lastName, email, password, role? } is allowed")
		}
	}
	for _, req := range []string{"email", "firstName", "lastName", "password"} {
		if _, ok := opts[req]; !ok {
			return nil, fmt.Errorf("ProtoThreat.user_create: firstName, lastName, email, and password are required")
		}
	}
	payload := map[string]any{
		"firstName": opts["firstName"], "lastName": opts["lastName"],
		"email": opts["email"], "password": opts["password"],
	}
	if v, ok := opts["role"]; ok && fmt.Sprint(v) != "" {
		payload["role"] = fmt.Sprint(v)
	}
	return p.Command(ctx, "user-create", payload)
}

// UserMe calls user-me.
func (p *ProtoThreat) UserMe(ctx context.Context) (any, error) {
	return p.Command(ctx, "user-me", map[string]any{})
}

// UserMeUpdate calls user-me-update.
func (p *ProtoThreat) UserMeUpdate(ctx context.Context, opts map[string]any) (any, error) {
	allowed := map[string]struct{}{"firstName": {}, "lastName": {}, "settings": {}}
	if len(opts) == 0 {
		return nil, fmt.Errorf("ProtoThreat.user_me_update: at least one field is required")
	}
	for k := range opts {
		if _, ok := allowed[k]; !ok {
			return nil, fmt.Errorf("ProtoThreat.user_me_update: unknown field %q", k)
		}
	}
	return p.Command(ctx, "user-me-update", maps.Clone(opts))
}

// UserSetRole calls user-set-role.
func (p *ProtoThreat) UserSetRole(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"id": {}, "role": {}}) {
		return nil, fmt.Errorf("ProtoThreat.user_set_role: only { id, role } is allowed")
	}
	return p.Command(ctx, "user-set-role", map[string]any{"id": opts["id"], "role": opts["role"]})
}

// UserProfile calls user-profile.
func (p *ProtoThreat) UserProfile(ctx context.Context, opts map[string]any) (any, error) {
	need := map[string]struct{}{"email": {}, "firstName": {}, "id": {}, "lastName": {}}
	if !setEq(keysString(opts), need) {
		return nil, fmt.Errorf("ProtoThreat.user_profile: only { id, firstName, lastName, email } is allowed")
	}
	return p.Command(ctx, "user-profile", map[string]any{
		"id": opts["id"], "firstName": opts["firstName"], "lastName": opts["lastName"], "email": opts["email"],
	})
}

// UserPassword calls user-password.
func (p *ProtoThreat) UserPassword(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"id": {}, "password": {}}) {
		return nil, fmt.Errorf("ProtoThreat.user_password: only { id, password } is allowed")
	}
	return p.Command(ctx, "user-password", map[string]any{"id": opts["id"], "password": opts["password"]})
}

// UserVerify calls user-verify.
func (p *ProtoThreat) UserVerify(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"email": {}, "password": {}}) {
		return nil, fmt.Errorf("ProtoThreat.user_verify: only { email, password } is allowed")
	}
	return p.Command(ctx, "user-verify", map[string]any{"email": opts["email"], "password": opts["password"]})
}

// UserRemove calls user-remove.
func (p *ProtoThreat) UserRemove(ctx context.Context, opts map[string]any) (any, error) {
	if !setEq(keysString(opts), map[string]struct{}{"id": {}}) {
		return nil, fmt.Errorf("ProtoThreat.user_remove: only { id } is allowed")
	}
	return p.Command(ctx, "user-remove", map[string]any{"id": opts["id"]})
}
