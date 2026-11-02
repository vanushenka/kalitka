// Package awg generates AmneziaWG configuration and drives the upstream tools.
// The protocol itself is amneziawg-go and amneziawg-tools; nothing here
// reimplements it.
package awg

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
)

const keySize = 32

// keyFormat also rejects line breaks, which the base64 decoder would skip. Keys
// end up in a config that awg-quick parses, so a line break must not get through.
var keyFormat = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

// GenerateKey returns a new base64 key, the equivalent of `awg genkey`.
func GenerateKey() string {
	raw := make([]byte, keySize)
	rand.Read(raw) // Never returns an error: it crashes the program instead.
	raw[0] &= 248
	raw[31] = raw[31]&127 | 64
	return base64.StdEncoding.EncodeToString(raw)
}

// PublicKey derives the public key, the equivalent of `awg pubkey`.
func PublicKey(private string) (string, error) {
	if err := ValidateKey(private); err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(private)
	if err != nil {
		return "", fmt.Errorf("decode key: %w", err)
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// ValidateKey checks that s is a base64 key of the size awg expects.
func ValidateKey(s string) error {
	if !keyFormat.MatchString(s) {
		return fmt.Errorf("not a %d-byte base64 key", keySize)
	}
	if _, err := base64.StdEncoding.DecodeString(s); err != nil {
		return fmt.Errorf("not a %d-byte base64 key: %w", keySize, err)
	}
	return nil
}
