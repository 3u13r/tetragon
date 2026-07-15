// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package keyring

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/require"
)

func TestParseKeySerials(t *testing.T) {
	payload := make([]byte, 8)
	binary.NativeEndian.PutUint32(payload[0:4], uint32(42))
	binary.NativeEndian.PutUint32(payload[4:8], uint32(1337))

	ids, err := parseKeySerials(payload)
	require.NoError(t, err)
	require.Equal(t, []int32{42, 1337}, ids)
}

func TestParseKeySerialsInvalidLength(t *testing.T) {
	_, err := parseKeySerials([]byte{1, 2, 3})
	require.Error(t, err)
}

func TestVerifyInKeyringECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ecdsa-test"},
		Issuer:                pkix.Name{CommonName: "ecdsa-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Minute),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	ringName := fmt.Sprintf("keyring-test-%d", time.Now().UnixNano())
	keyringID, err := unix.KeyctlJoinSessionKeyring(ringName)
	require.NoError(t, err)

	keyID, err := unix.AddKey("asymmetric", "ecdsa-test", certDER, keyringID)
	require.NoError(t, err)

	data := []byte("keyring verify test payload")
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	require.NoError(t, err)

	verifyErr := verifyWithKey(int32(keyID), digest[:], sig)
	require.NoError(t, verifyErr)

	err = VerifySignatures(int32(keyringID), digest[:], []string{hex.EncodeToString(sig)})
	require.NoError(t, err)
}

// TestVerifySignaturesMultipleKeys covers VerifySignatures behavior when the
// keyring holds multiple keys and/or multiple signatures are provided,
// including keys that are absent from the keyring, revoked, or expired. As
// long as at least one signature can be verified by a usable key, the overall
// call must succeed; if none can, it must fail with ErrSignatureNotVerified.
func TestVerifySignaturesMultipleKeys(t *testing.T) {
	const (
		keyNameValid   = "valid"
		keyNameRevoked = "revoked"
		keyNameExpired = "expired"
		keyNameAbsent  = "absent"
	)

	// Fixed pool of named keys shared across all subtests.
	names := []string{keyNameValid, keyNameRevoked, keyNameExpired, keyNameAbsent}
	privs := make(map[string]*ecdsa.PrivateKey, len(names))
	certs := make(map[string][]byte, len(names))
	for _, name := range names {
		priv, cert := genTestKey(t, name)
		privs[name] = priv
		certs[name] = cert
	}

	data := []byte("keyring multi-signature test payload")
	digest := sha256.Sum256(data)

	garbageSignature := hex.EncodeToString([]byte("this-is-not-a-real-signature"))

	tests := map[string]struct {
		keysInKeyring []string
		signerNames   []string

		includeGarbageSignature bool
		wantErr                 bool
	}{
		"single valid signature succeeds": {
			keysInKeyring: []string{keyNameValid},
			signerNames:   []string{keyNameValid},
			wantErr:       false,
		},
		"one valid and one garbage signature succeeds": {
			keysInKeyring:           []string{keyNameValid},
			signerNames:             []string{keyNameValid},
			includeGarbageSignature: true,
			wantErr:                 false,
		},
		"only garbage signatures fail": {
			keysInKeyring:           []string{keyNameValid},
			includeGarbageSignature: true,
			wantErr:                 true,
		},
		"signature from a key absent from the keyring fails": {
			keysInKeyring: []string{keyNameValid},
			signerNames:   []string{keyNameAbsent},
			wantErr:       true,
		},
		"signature from an absent key plus a valid signature succeeds": {
			keysInKeyring: []string{keyNameValid},
			signerNames:   []string{keyNameAbsent, keyNameValid},
			wantErr:       false,
		},
		"signature from a revoked key alone fails": {
			keysInKeyring: []string{keyNameRevoked},
			signerNames:   []string{keyNameRevoked},
			wantErr:       true,
		},
		"signature from a revoked key plus a valid signature succeeds": {
			keysInKeyring: []string{keyNameRevoked, keyNameValid},
			signerNames:   []string{keyNameRevoked, keyNameValid},
			wantErr:       false,
		},
		"signature from an expired key alone fails": {
			keysInKeyring: []string{keyNameExpired},
			signerNames:   []string{keyNameExpired},
			wantErr:       true,
		},
		"signature from an expired key plus a valid signature succeeds": {
			keysInKeyring: []string{keyNameExpired, keyNameValid},
			signerNames:   []string{keyNameExpired, keyNameValid},
			wantErr:       false,
		},
	}

	for testName, tc := range tests {
		t.Run(testName, func(t *testing.T) {
			// Linux keyring "possession" (keyrings(7)) is tied to the calling
			// thread's own credentials: a thread only possesses a process
			// keyring it installed itself, and installing one lazily only
			// updates that thread's credentials (process-keyring(7): sharing
			// across threads happens at clone(CLONE_THREAD) time, not
			// retroactively). Since this subtest blocks on time.Sleep (a
			// scheduling point), the goroutine could otherwise resume on a
			// different OS thread that doesn't possess the keyring, causing
			// later keyctl calls (e.g. KEYCTL_READ) to fail with EACCES
			// despite using the same numeric IDs throughout. Pin the OS
			// thread for the whole subtest to avoid that.
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			ringName := fmt.Sprintf("keyring-multisig-test-%d", time.Now().UnixNano())
			keyringID, err := unix.AddKey("keyring", ringName, nil, unix.KEY_SPEC_PROCESS_KEYRING)
			require.NoError(t, err)

			for _, name := range tc.keysInKeyring {
				// Use a description unique to this subtest (rather than just
				// name) so that re-adding a key with the same description as
				// one already revoked/expired in an earlier subtest can't
				// collide with the kernel's existing key matching.
				desc := name + "-" + ringName
				keyID, err := unix.AddKey("asymmetric", desc, certs[name], keyringID)
				require.NoError(t, err)

				switch name {
				case keyNameRevoked:
					_, err := unix.KeyctlInt(unix.KEYCTL_REVOKE, keyID, 0, 0, 0)
					require.NoError(t, err)
				case keyNameExpired:
					// Set the shortest possible timeout and wait for it to
					// elapse so the key is treated as expired by the kernel.
					_, err := unix.KeyctlInt(unix.KEYCTL_SET_TIMEOUT, keyID, 1, 0, 0)
					require.NoError(t, err)
					time.Sleep(1200 * time.Millisecond)
				}
			}

			signatures := make([]string, 0, len(tc.signerNames)+1)
			for _, name := range tc.signerNames {
				signatures = append(signatures, signDigest(t, privs[name], digest[:]))
			}
			if tc.includeGarbageSignature {
				signatures = append(signatures, garbageSignature)
			}

			err = VerifySignatures(int32(keyringID), digest[:], signatures)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorIs(t, err, ErrSignatureNotVerified)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// genTestKey generates an ECDSA key pair together with a self-signed
// certificate suitable for linking into a keyring as an "asymmetric" key.
func genTestKey(t *testing.T, commonName string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		Issuer:                pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Minute),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	return priv, certDER
}

// signDigest signs data (already hashed with SHA-256) with priv and returns the
// hex-encoded ASN.1 signature, matching the format expected by VerifySignatures.
func signDigest(t *testing.T, priv *ecdsa.PrivateKey, digest []byte) string {
	t.Helper()

	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	require.NoError(t, err)
	return hex.EncodeToString(sig)
}
