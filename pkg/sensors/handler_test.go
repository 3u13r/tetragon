// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// referenceTracingPolicySpecForSigning is a fixed TracingPolicySpec used during
// testing to confirm that struct changes don't unintentionally break existing signatures.
func referenceTracingPolicySpecForSigning() *v1alpha1.TracingPolicySpec {
	return &v1alpha1.TracingPolicySpec{
		KProbes: []v1alpha1.KProbeSpec{
			{
				Call:    "sys_openat",
				Return:  true,
				Syscall: true,
				Message: "reference kprobe",
				Args: []v1alpha1.KProbeArg{
					{Index: 0, Type: "int"},
				},
			},
		},
		Loader: true,
		Lists: []v1alpha1.ListSpec{
			{
				Name:   "reference-list",
				Values: []string{"a", "b"},
				Type:   "syscalls",
			},
		},
		Options: []v1alpha1.OptionSpec{
			{Name: "reference-option", Value: "reference-value"},
		},
		SelectorsMacros: map[string]v1alpha1.KProbeSelector{
			"reference-macro": {},
		},
		// Signatures is intentionally populated here to confirm
		// canonicalTracingPolicySpecBytes clears it before marshaling.
		Signatures: []string{"deadbeef"},
	}
}

// TestCanonicalTracingPolicySpecBytesStability pins the marshaled bytes of a reference TracingPolicySpec.
// If this changes, we know that we invalidate existing signatures, which we have to be intentional about.
func TestCanonicalTracingPolicySpecBytesStability(t *testing.T) {
	const wantDigestHex = "59740d72ce419030d4916aece9d1e27d3e60f37b140433f09855b02f0fa1899a"

	spec := referenceTracingPolicySpecForSigning()

	tpBytes, err := canonicalTracingPolicySpecBytes(spec)
	require.NoError(t, err)

	digest := sha256.Sum256(tpBytes)
	gotDigestHex := hex.EncodeToString(digest[:])

	require.Equal(t, wantDigestHex, gotDigestHex,
		"canonical TracingPolicySpec encoding changed - see the comment on this test before updating the pinned digest")
}

// TestCanonicalTracingPolicySpecBytesClearsSignatures confirms Signatures is
// never part of the signed bytes, regardless of its contents.
func TestCanonicalTracingPolicySpecBytesClearsSignatures(t *testing.T) {
	withSignatures := referenceTracingPolicySpecForSigning()
	withSignatures.Signatures = []string{"one-signature"}

	withDifferentSignatures := referenceTracingPolicySpecForSigning()
	withDifferentSignatures.Signatures = []string{"another-signature", "yet-another"}

	bytesA, err := canonicalTracingPolicySpecBytes(withSignatures)
	require.NoError(t, err)
	bytesB, err := canonicalTracingPolicySpecBytes(withDifferentSignatures)
	require.NoError(t, err)

	require.Equal(t, bytesA, bytesB)
}
