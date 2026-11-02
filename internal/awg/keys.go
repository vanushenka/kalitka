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

var (
	// keyFormat refuses line breaks, which even the strict base64 decoder skips. Keys
	// end up in a config that awg-quick parses, so a line break must not get through.
	keyFormat = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	// keyEncoding refuses non-zero trailing bits, as awg does.
	keyEncoding = base64.StdEncoding.Strict()
	zeroKey     = keyEncoding.EncodeToString(make([]byte, keySize))
)

// GenerateKey returns a new base64 key, the equivalent of `awg genkey`.
func GenerateKey() string {
	raw := make([]byte, keySize)
	rand.Read(raw) // Never returns an error: it crashes the program instead.
	raw[0] &= 248
	raw[31] = raw[31]&127 | 64
	return keyEncoding.EncodeToString(raw)
}

// PublicKey derives the public key, the equivalent of `awg pubkey`.
func PublicKey(private string) (string, error) {
	raw, err := decodeKey(private)
	if err != nil {
		return "", err
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", fmt.Errorf("parse key: %w", err)
	}
	return keyEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// ValidateKey checks that s is a base64 key that awg will accept.
func ValidateKey(s string) error {
	_, err := decodeKey(s)
	return err
}

func decodeKey(s string) ([]byte, error) {
	if !keyFormat.MatchString(s) {
		return nil, fmt.Errorf("not a %d-byte base64 key", keySize)
	}
	raw, err := keyEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not a %d-byte base64 key: %w", keySize, err)
	}
	return raw, nil
}
