// Package awg generates AmneziaWG configuration and runs the upstream engine,
// amneziawg-go, inside this process. Nothing here reimplements the protocol.
package awg

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
)

const keySize = 32

var (
	// keyFormat refuses line breaks, which even the strict base64 decoder skips.
	keyFormat = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)
	// keyEncoding refuses non-zero trailing bits. Peers using other WireGuard tools
	// would refuse such a key.
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

// ValidateKey checks that s is a canonical base64 key.
func ValidateKey(s string) error {
	_, err := decodeKey(s)
	return err
}

// keyHex converts a key to the form the engine's config takes.
func keyHex(s string) (string, error) {
	raw, err := decodeKey(s)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
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
