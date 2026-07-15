// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package sensors

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/option"
)

// TestAddPolicyRequireSignature exercises tracing policy signature
// verification end-to-end against the real Linux keyring: it links an
// asymmetric key into a fresh session keyring using real keyctl(2) syscalls
// (no mocking), then verifies that AddTracingPolicy accepts a policy signed
// by that key and rejects policies with an invalid or missing signature.
func TestAddPolicyRequireSignature(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	RegisterPolicyHandlerAtInit("dummy", &dummyHandler{s: &Sensor{Name: "dummy-sensor"}})
	t.Cleanup(func() {
		delete(registeredPolicyHandlers, "dummy")
	})

	// Generate a real ECDSA key and self-signed cert, then link it into a
	// fresh session keyring - the same asymmetric-key/keyctl mechanism used
	// in production.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tetragon-test"},
		Issuer:                pkix.Name{CommonName: "tetragon-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Minute),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	ringName := fmt.Sprintf("tetragon-sensors-test-%d", time.Now().UnixNano())
	keyringID, err := unix.KeyctlJoinSessionKeyring(ringName)
	require.NoError(t, err)

	_, err = unix.AddKey("asymmetric", "tetragon-test-key", certDER, keyringID)
	require.NoError(t, err)

	oldRequireSignature := option.Config.RequireSignature
	oldKeyringID := option.Config.KeyringID
	option.Config.RequireSignature = true
	option.Config.KeyringID = int32(keyringID)
	t.Cleanup(func() {
		option.Config.RequireSignature = oldRequireSignature
		option.Config.KeyringID = oldKeyringID
	})

	mgr, err := StartSensorManager("")
	require.NoError(t, err)

	// sign mirrors handler.verifyTracingPolicySignature: it marshals the
	// spec (with Signatures cleared) to JSON, hashes it with SHA-256, and
	// signs the digest.
	sign := func(spec *v1alpha1.TracingPolicySpec) string {
		specCopy := spec.DeepCopy()
		specCopy.Signatures = nil
		specBytes, err := json.Marshal(specCopy)
		require.NoError(t, err)
		digest := sha256.Sum256(specBytes)
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
		require.NoError(t, err)
		return hex.EncodeToString(sig)
	}

	// A policy signed with the linked key must load successfully.
	validPolicy := v1alpha1.TracingPolicy{}
	validPolicy.Name = "signed-policy"
	validPolicy.Spec.Signatures = []string{sign(&validPolicy.Spec)}
	err = mgr.AddTracingPolicy(ctx, &validPolicy)
	require.NoError(t, err)

	// A policy with a bogus signature must be rejected.
	badSigPolicy := v1alpha1.TracingPolicy{}
	badSigPolicy.Name = "bad-signature-policy"
	badSigPolicy.Spec.Signatures = []string{hex.EncodeToString([]byte("not-a-real-signature"))}
	err = mgr.AddTracingPolicy(ctx, &badSigPolicy)
	require.Error(t, err)
	t.Logf("got error (as expected): %s", err)

	// A policy with no signature at all must also be rejected.
	noSigPolicy := v1alpha1.TracingPolicy{}
	noSigPolicy.Name = "no-signature-policy"
	err = mgr.AddTracingPolicy(ctx, &noSigPolicy)
	require.Error(t, err)
	t.Logf("got error (as expected): %s", err)
}
