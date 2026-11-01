package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Fingerprint names a key the way the server does: SHA-256 of the raw Ed25519 public key, base64url, no padding.
func Fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// DeviceKey is this device's own identity. The server knows the device by the key's fingerprint, so there is
// no name for anyone else to claim. The private key never leaves the state directory (file mode 0600).
type DeviceKey struct{ private ed25519.PrivateKey }

func (k DeviceKey) PublicRaw() []byte    { return k.private.Public().(ed25519.PublicKey) }
func (k DeviceKey) PublicBase64() string { return base64.StdEncoding.EncodeToString(k.PublicRaw()) }
func (k DeviceKey) DeviceID() string     { return Fingerprint(k.PublicRaw()) }

// Sign signs "<timestamp>:<body>", what the server verifies.
func (k DeviceKey) Sign(timestamp string, body []byte) string {
	msg := append([]byte(timestamp+":"), body...)
	return base64.StdEncoding.EncodeToString(ed25519.Sign(k.private, msg))
}

// LoadOrCreateKey reads the seed from dir/device.key, or makes one. A key file anyone else can read is refused.
func LoadOrCreateKey(dir string) (DeviceKey, error) {
	path := filepath.Join(dir, "device.key")
	if info, err := os.Stat(path); err == nil {
		if info.Mode().Perm()&0o077 != 0 {
			return DeviceKey{}, fmt.Errorf("%s is readable by others (mode %o); it must be 0600", path, info.Mode().Perm())
		}
		seed, err := os.ReadFile(path)
		if err != nil {
			return DeviceKey{}, err
		}
		if len(seed) != ed25519.SeedSize {
			return DeviceKey{}, errors.New(path + " is not an Ed25519 seed")
		}
		return DeviceKey{ed25519.NewKeyFromSeed(seed)}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return DeviceKey{}, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return DeviceKey{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return DeviceKey{}, err
	}
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		return DeviceKey{}, err
	}
	handOver(dir)
	handOver(path)
	return DeviceKey{ed25519.NewKeyFromSeed(seed)}, nil
}
